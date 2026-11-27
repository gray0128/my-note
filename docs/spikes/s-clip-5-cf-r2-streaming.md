# S-Clip-5 实测报告：Cloudflare Worker 流式直传 R2 与 `clip/blobs/` 前缀生命周期（Issue #53）

- **当前状态**：**全部通过（`pass`）**——本地真实 `workerd` 流式读写测试 **5/5 通过**（`163 LOC` TS `[已测]`），真实个人 Cloudflare Paid 账号生产桶 `mynote-archive` 已写入并回读确认 `clip/blobs/` **8 天**前缀生命周期规则（与既有 `archives/keys/history/` 30 天规则及默认 7 天分片中止规则共存，`archives/ops/` 与 `archives/keys/latest.mnks` 均无过期规则），且完成 `clip/blobs/_s_clip_5_probe.mnc1` 实桶上传、下载 SHA-256 校验与清理归零 `[已测]`。
- **验证日期与环境**：2026-11-27；本机 macOS `27.2.1`（`arm64`）、Node.js `v26.13.1`、pnpm `12.18.0`、Vitest `4.1.12`、`@cloudflare/vitest-pool-workers 0.23.0`、`wrangler 4.168.0`、`workerd 1.20261123.1`（及 `1.20260815.1`）、`cf v1.0.0-beta.13`（真实 Cloudflare Paid 账号）。
- **复现路径**：[`spikes/s-clip-5-cf-r2-streaming/`](../../spikes/s-clip-5-cf-r2-streaming/)（执行 `pnpm --dir spikes/s-clip-5-cf-r2-streaming typecheck && pnpm --dir spikes/s-clip-5-cf-r2-streaming test`）。

---

## 1. 真实 `workerd` 流式 R2 读写实测（全部为 `[已测]`）

原型 Worker [`spikes/s-clip-5-cf-r2-streaming/src/index.ts`](../../spikes/s-clip-5-cf-r2-streaming/src/index.ts)（`163 LOC` `[已测]`）全程零调用 `req.arrayBuffer()` / `req.bytes()` / `req.blob()` / `obj.arrayBuffer()`，实现 `PUT /v1/clip/blob`、`GET /v1/clip/:id/blob` 与 `DELETE /v1/clip/:id/blob`，并在 [`test/streaming.test.ts`](../../spikes/s-clip-5-cf-r2-streaming/test/streaming.test.ts) 中验证以下 5 项场景：

| 验证项 | 验证手段（`test/streaming.test.ts`） | 实测结果 `[已测]` |
| --- | --- | --- |
| **10 MiB 流式上传 + 流式下载 SHA-256 校验 + 删除** | `ReadableStream` 按 `64 KiB` 分块生成 `10,485,760 B`（`10 MiB`）确定性 `MNC1` 前缀载荷 → `PUT /v1/clip/blob` 流式写 R2 `clip/blobs/<id>.mnc1` → `GET /v1/clip/:id/blob` 用 `crypto.DigestStream("SHA-256")` 逐块流式校验 → `DELETE` 后二次 `GET` | ✅ 通过：`PUT` **`80 ms`**、`GET` + 流式校验 **`21 ms`**（收到 **`2,560` 个 `4 KiB` 独立分块**，证明非整块缓冲），SHA-256 `bd1d2cc590348e1b0337f856f260ccdcf75b3ab3c753cb019f40e020c56ddeef` 完全一致；删除后 `GET` 返回 `404 NOT_FOUND` 且 `ARCHIVE_BUCKET.head()` 为 `null` |
| **`10.5 MiB` 精确边界与超限拒收** | 精确 `10.5 MiB`（`11,010,048 B`）流式上传；`10.5 MiB + 1 B`（`11,010,049 B`）请求 | ✅ 通过：`11,010,048 B` 返回 `200` 并成功写入后清理；`11,010,049 B` 立即取消请求流并返回 **`413 PAYLOAD_TOO_LARGE`**，R2 零写入（`head()` 为 `null`、`GET` 返回 `404`） |
| **缺失 / 零值 `Content-Length` 拦截** | `Content-Length: 0` 与缺失 `Content-Length` 的 `PUT /v1/clip/blob` | ✅ 通过：均返回 **`400 INVALID_ARGUMENT`** 且 R2 零写入 |
| **伪造 / 截断 `Content-Length` 流攻击防护** | ① 头部声称 `1024 B` 但实际流发送 `8192 B`（超发）；② 头部声称 `8192 B` 但实际流在 `1024 B` 处提前关闭（截断） | ✅ 通过：`FixedLengthStream` 在流式传输中立即中止并报错，Worker 返回 **`400 CONTENT_LENGTH_MISMATCH`** 并执行兜底 `delete`，R2 零孤儿对象（`head()` 均为 `null`） |
| **连续 `3 × 10 MiB` 往返压力** | 连续执行 3 轮 `10 MiB` 流式 `PUT` + 流式 `GET` 校验 + `DELETE`（累计上传 `30 MiB` + 下载 `30 MiB` = `60 MiB`） | ✅ 通过：总耗时 **`295 ms`**，3 轮 SHA-256 全部一致，无缓冲累积报错 |

---

## 2. Spike 提前捕获的关键 `workerd` 工程实坑（直接指导 M4a `cloud-cf` 实现）

本次 Spike 在真实 `workerd` 中捕获了 3 个必须在 M4a `cloud-cf/src/index.ts` 中编码解决的真实运行时细节：

1. **【核心发现】不能直接把未知长度的 `req.body` 传给 `R2Bucket.put`——必须经 `FixedLengthStream(contentLength)` 零缓冲转发**：
   - 初版原型直接调用 `await env.ARCHIVE_BUCKET.put(key, req.body)` 时，在真实 `workerd` 下立即抛出：
     ```text
     TypeError: Provided readable stream must have a known length (request/response body or readable half of FixedLengthStream)
     ```
   - 原因：当客户端通过 `ReadableStream`（以及 HTTP/2、HTTP/3 或 `Transfer-Encoding: chunked`）发起流式 `PUT` 时，即使携带了 `Content-Length` 请求头，`req.body` 在运行时仍可能不携带内部定长流描述符。
   - **根治写法（零缓冲 + 防伪造长度）**：在校验 `0 < contentLength <= 11_010_048` 后，构造 `const fixed = new FixedLengthStream(contentLength)`，并行执行 `req.body.pipeTo(fixed.writable)` 与 `env.ARCHIVE_BUCKET.put(key, fixed.readable, ...)`，并用 `Promise.allSettled([pipePromise, putPromise])` 统一收口。这样既保持 O(1) 常量内存与原生背压（零 `arrayBuffer()`），又能强拦截客户端伪造小 `Content-Length` 却持续超发字节的攻击，以及弱网中途断流产生的半截上传；任意一方失败时统一清理 R2 键并返回 `400 CONTENT_LENGTH_MISMATCH`（或 `500`）。
2. **早期拒绝路径必须显式 `await req.body.cancel()`**：
   - 对 `400` / `413` / `403` 等早期拒绝路径，取消未消费的 `req.body` 流可避免 `workerd` 在响应发送后触发流状态异常；同时避免像 `req.arrayBuffer()` 那样把超限恶意载荷读进内存。
3. **测试工具链与 `pnpm 12` 兼容提示**：
   - `workerd` 测试输出提示 `@cloudflare/vitest-pool-workers` 已更名为 `@cloudflare/vitest-plugin`（当前原型与 `cloud-cf/` 保持一致使用 `0.23.0`）；此外 `pnpm 12` 需在包目录内通过 `pnpm-workspace.yaml` 声明 `allowBuilds: { esbuild: true, workerd: true }` 才能执行 `workerd` 二进制安装脚本。
   - **测试边界诚实声明**：本地 `workerd` / Miniflare 实测证明了代码零全量缓冲、分块流式传输（`2,560 × 4 KiB`）与 `FixedLengthStream` 精确长度约束，但本地 Miniflare 并不等同于 Cloudflare 生产边缘 128 MB V8 Isolate 硬 OOM 杀进程机制；边缘真环境 10 MiB 上传验证将在 M4a 经 CI-only 部署后补测。

---

## 3. 真实 Cloudflare Paid 生产桶 `mynote-archive` 验证结果（全部为 `[已测]`）

所有 `cf` 命令均在 `/tmp` 下执行，未在仓库根目录产生 `.cloudflare/` 目录；临时规则文件与探针文件均已在验证结束后清理。

### 3.1 `mynote-archive` 生命周期规则更新与回读

执行 `(cd /tmp && cf r2 buckets lifecycle update mynote-archive --rules @/tmp/mynote-archive-lifecycle.json -f)` 后，通过 `(cd /tmp && cf r2 buckets lifecycle get mynote-archive)` 回读确认全部 3 条规则同时生效：

```json
{
  "rules": [
    {
      "id": "Default Multipart Abort Rule",
      "enabled": true,
      "conditions": {},
      "abortMultipartUploadsTransition": {
        "condition": {
          "type": "Age",
          "maxAge": 604800
        }
      }
    },
    {
      "id": "expire-clip-blobs-8d",
      "enabled": true,
      "conditions": {
        "prefix": "clip/blobs/"
      },
      "deleteObjectsTransition": {
        "condition": {
          "type": "Age",
          "maxAge": 691200
        }
      }
    },
    {
      "id": "expire-key-history-30d",
      "enabled": true,
      "conditions": {
        "prefix": "archives/keys/history/"
      },
      "deleteObjectsTransition": {
        "condition": {
          "type": "Age",
          "maxAge": 2592000
        }
      }
    }
  ]
}
```

| 核验项 | 预期要求 | 实测结论（2026-11-27 真实 CF Paid 账号） |
| --- | --- | --- |
| **`clip/blobs/` 8 天前缀生命周期** | `prefix: "clip/blobs/"`，`Age: 691200`（8 天） | ✅ `[已测]` `expire-clip-blobs-8d` 已启用，作为 DO 主动 `R2.delete` 之外的孤儿对象兜底清理 |
| **既有规则零破坏与永久前缀保护** | 保留 `Default Multipart Abort Rule`（7 天）与 `expire-key-history-30d`（30 天）；`archives/ops/` 与 `archives/keys/latest.mnks` 无过期规则 | ✅ `[已测]` 回读确认 3 条规则完整并存，`archives/ops/` 与 `archives/keys/latest.mnks` 均无任何过期规则 |
| **Bucket Lock 状态确认** | 检查 `mynote-archive` 当前保留锁配置 | ✅ `[已测]` `cf r2 buckets locks get mynote-archive` 返回 `{"rules": []}`（当前无全局或前缀锁；且按 [S0-4 实测报告](./s0-4-cloudflare-relay.md)，即使后续对 `archives/ops/` 开启前缀锁，也不影响不相交前缀 `clip/blobs/` 的写入与删除） |
| **真实 R2 `clip/blobs/` 读写删探针** | 上传 `clip/blobs/_s_clip_5_probe.mnc1`、校验下载内容、删除并确认零残留 | ✅ `[已测]` 上传 `65,536 B` `application/octet-stream`（`etag: af379922ae19182a14beb9857206ecc5`，`storage_class: Standard`，`uploaded: 2026-11-27T05:41:33.805Z`）；`list` 确认存在；`get` 回读 `65,536 B` 且 SHA-256 `0e415516ec6959324b7ce159e96a57ad3f2c06c995c2549359f6e37d77eec7e0` 与源文件完全一致（`exact_match=true`）；`delete` 后再次 `list --prefix clip/blobs/` 返回 `[]`，零残留对象 |

---

## 4. 对 M4a（`cloud-cf/`）的落地建议

1. **`PUT /v1/clip/blob` 强制经 `FixedLengthStream(contentLength)` 管道写入 R2**：在鉴权、令牌范围校验（`read-write` / `read+clip` / `clip-write`）、`X-Clip-Id` / `X-Clip-Meta-B64` 校验与 `0 < Content-Length <= 11_010_048` 校验之后，立即以 `req.body.pipeTo(fixed.writable)` + `env.ARCHIVE_BUCKET.put(r2Key, fixed.readable)` 并发流式直写 R2，严禁退回 `req.arrayBuffer()` 或直接传入未包装的 `req.body`。
2. **孤儿清理双保险**：`R2.put` 成功后若 DO `clip_items` 事务登记失败（或 `FixedLengthStream` 报错中断），Worker 在同一请求内立即执行 `env.ARCHIVE_BUCKET.delete(r2Key)`；若极端网络/进程故障仍遗留孤儿，生产桶 `mynote-archive` 上已生效的 `expire-clip-blobs-8d` 生命周期规则将在 8 天后自动清除。
3. **`GET /v1/clip/:clip_id/blob` 流式直出**：经 DO 校验 `clip_id` 存在且未过期后，直接返回 `new Response(obj.body, { headers: { "Content-Type": "application/octet-stream", "Content-Length": String(obj.size), ETag: obj.httpEtag, ... } })`，不在 Worker 内存缓存响应体。
4. **`ADR-11` 状态说明**：S-Clip-5 已通过 `workerd` 与真实 Cloudflare Paid R2 全部验证；`ADR-11` 整体升为 `Accepted` 仍需汇总 S-Clip-1 至 S-Clip-4 的对应真机证据。
