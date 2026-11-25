# S0-3 实测报告：`mynote-wasm` 体积基线、压缩方案选型与 iPhone 真机 Argon2id 基准（Issue #34）

- **结论（已闭环，支撑 `ADR-01` 与 `ADR-06` 转为 `Accepted`）**：
  1. **WASM 体积基线全部达标且留有充足余量**：采用纯 Rust `ruzstd 0.9.1`（零 C 工具链依赖，与桌面原生 `zstd 0.14.5` 双向帧兼容已通过单测验证）+ 关闭 `x25519-dalek/precomputed-tables`（立省 `27.8 KiB` gzip），**手机只读 PWA WASM 仅 `71.5 KiB` gzip** [已测]，**桌面全功能 WASM（密码学 + `ruzstd` 编解码 + Layer 1 格式化器）仅 `260.4 KiB` gzip** [已测]，远低于 `< 350 KiB` 目标。据此将 **`ADR-01` 升级为 `Accepted`**。
  2. **iPhone 真机（主屏独立 PWA）Argon2id 参数拍板**：2026-11-25 在真机 iPhone（iOS 18.7 / WebKit 605.1.15 / Safari 27.2，**添加到主屏幕后的 Standalone PWA**）实测 7 组参数全部零 OOM 通过（含 64 MiB 峰值 `65.19 MiB`、`smokeRc = 1000`），但真机耗时约为 Linux WebKit 的 **10–11 倍**——原暂定值 `(65536, 3, 1)` 实测高达 **`4812 ms`** [已测]，**正式否决**；最终拍板 **`VaultHeaderV1` 唯一默认 KDF 参数为 `(m_kib = 32768, t = 2, p = 1)`**（32 MiB 内存、2 轮、单线程，iPhone 主屏 PWA 中位耗时 **`1553 ms`** [已测]，稳落 `1–2 s` 目标区间且高于 OWASP 19 MiB 下限），同步固化至 `docs/data-structures.md` 与 `mynote-core` 默认常量，支撑 **`ADR-06` 升级为 `Accepted`**。
- **复现路径**：[`spikes/s0-3-wasm-argon2/`](../../spikes/s0-3-wasm-argon2/)（`./measure.sh`、`cargo test --features comp-ruzstd-rw,comp-zstd-c`、`python3 run_browser_bench.py`、`bench.html`）。

---

## 1. `wasm32-unknown-unknown` 体积实测基线（`rustc 1.100.0` + `opt-level="z"` + `lto=true` + `wasm-opt -Oz` + `gzip -9`）

| 构建配置 | 原始 `.wasm` | `wasm-opt -Oz` | `gzip -9` | 说明 |
| --- | ---: | ---: | ---: | --- |
| `1-crypto-only`（XChaCha20-Poly1305 + Argon2id + HKDF/SHA2 + BLAKE3 pure + X25519 无预计算表 + `rmp-serde` + `zeroize`） | 129.6 KiB | 114.2 KiB | **47.3 KiB** [已测] | 纯密码学底座 |
| `2-crypto-x25519-precomp`（开启 `x25519-dalek/precomputed-tables`） | 159.1 KiB | 143.9 KiB | **75.1 KiB** [已测] | 仅恢复封装低频调用，**关闭以省 27.8 KiB** |
| `3-mobile-ruzstd-decode`（**手机只读 PWA 目标配置**：密码学 + `ruzstd` 解压） | 206.6 KiB | 180.5 KiB | **71.5 KiB** [已测] | 仅占 350 KiB 预算的 20.4% |
| `4-desktop-ruzstd-rw`（密码学 + `ruzstd` 纯 Rust 压缩与解压） | 252.5 KiB | 222.6 KiB | **88.4 KiB** [已测] | 零 C 工具链，双向帧与 C `zstd` 完全兼容（macOS `wasm-opt 133` 复现 `222.1 KiB / 227,467 B`） |
| `5-desktop-miniz-rw`（对照：`miniz_oxide` Deflate） | 165.1 KiB | 146.9 KiB | **61.6 KiB** [已测] | 仅作对比；`ruzstd` 仅多 26.8 KiB 且免改 `zstd` 线格式 |
| `6-desktop-ruzstd-layer1`（**桌面全功能**：`4` + `serde_json` + `toml` + `serde_yaml_ng` + `sqlformat` + `quick-xml`） | 699.8 KiB | 624.3 KiB | **260.4 KiB** [已测] | 低于 `< 350 KiB` 目标，余量 ~90 KiB 给 `wasm-bindgen` 与 `WasmSyncEngine` |
| `7-desktop-zstd-c`（C 绑定 `zstd 0.14.5` / `zstd-sys`） | 580.2 KiB | 490.4 KiB | **167.6 KiB** [已测] | 比纯 Rust `ruzstd` 胖 **+79.2 KiB** 且依赖 C 交叉编译，**否决** |

- **帧互通验证**：`cargo test --features comp-ruzstd-rw,comp-zstd-c` 通过（空串、短文本、500x JSON、200x CJK/Emoji 全部验证 `zstd::encode_all` → `ruzstd::StreamingDecoder` 与 `ruzstd::encoding::compress_to_vec` → `zstd::decode_all` 字节级无损往返）。
- **依赖选型拍板**：
  - 桌面原生核心（`mynote-core` native）与 `mynote-wasm` 均采用 **纯 Rust `ruzstd`**（手机构建仅解压端、桌面构建含编解码端）并**禁用 `x25519-dalek/precomputed-tables`**；保留 `MNB1` 的 `zstd` 线格式不变。

---

## 2. Argon2id WASM 耗时与线性内存实测（3 次中位数，`4-desktop-ruzstd-rw.opt.wasm` = `227,467 B`）

- **iPhone 真机环境**：`Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1`（经 Safari「添加到主屏幕」以独立 PWA 运行；`smokeRc = 1000`，`smokeHashPrefix = bbe1e1fd2f7b6525`）。

| 参数 `(m_kib, t, p)` | 内存 `m` | Chromium 159 (V8, Linux x64) | WebKit 27.2 (JSC, Linux x64) | 峰值 WASM 线性内存 | iPhone 主屏 PWA 真机（中位 / 3 次采样） | 结论 |
| --- | ---: | ---: | ---: | ---: | --- | :---: |
| `(19456, 2, 1)`（OWASP 下限） | 19 MiB | 74.7 ms [已测] | 85 ms [已测] | 20.19 MiB [已测] | **928 ms** `[925, 928, 928]` [已测] | 偏轻 |
| `(19456, 3, 1)` | 19 MiB | 101.2 ms [已测] | 122 ms [已测] | 20.19 MiB [已测] | **1411 ms** `[1415, 1411, 1407]` [已测] | 内存低于 32 MiB |
| **`(32768, 2, 1)`（已拍板默认值）** | **32 MiB** | **125.3 ms** [已测] | **153 ms** [已测] | **33.19 MiB** [已测] | **1553 ms** `[1557, 1549, 1553]` [已测] | **✅ 选定** |
| `(32768, 3, 1)` | 32 MiB | 171.2 ms [已测] | 214 ms [已测] | 33.19 MiB [已测] | **2389 ms** `[2460, 2389, 2386]` [已测] | 劣于 46 MiB / t=2 |
| `(47104, 2, 1)`（OWASP 46 MiB） | 46 MiB | 180.2 ms [已测] | 209 ms [已测] | 47.19 MiB [已测] | **2242 ms** `[2242, 2237, 2255]` [已测] | 略超 2s |
| `(65536, 2, 1)` | 64 MiB | 258.8 ms [已测] | 335 ms [已测] | 65.19 MiB [已测] | **3136 ms** `[3120, 3136, 3145]` [已测] | 偏慢 |
| `(65536, 3, 1)`（原暂定值） | 64 MiB | 367.5 ms [已测] | 433 ms [已测] | 65.19 MiB [已测] | **4812 ms** `[4817, 4805, 4812]` [已测] | **❌ 否决（近 5s）** |

- **关键收获**：Linux WebKit 模拟结果与 iPhone 真机存在约 **10× 性能差距**，真机实测直接避免了把原暂定值 `(65536, 3, 1)`（4.8 秒解锁卡顿）带入线上；同时确认 iPhone 主屏独立 PWA 在 64 MiB 档位亦无内存闪退，选定 `(32768, 2, 1)`（峰值 `33.19 MiB`、耗时 `1.55 s`）兼具抗破解强度、内存安全余量与解锁体感。
