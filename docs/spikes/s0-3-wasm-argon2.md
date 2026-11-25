# S0-3 实测报告：`mynote-wasm` 体积基线、压缩方案选型与 Argon2id 基准（Issue #34）

- **结论**：
  1. **WASM 体积基线全部达标且留有充足余量**：采用纯 Rust `ruzstd 0.9.1`（零 C 工具链依赖，与桌面原生 `zstd 0.14.5` 双向帧兼容已通过单测验证）+ 关闭 `x25519-dalek/precomputed-tables`（立省 `27.8 KiB` gzip），**手机只读 PWA WASM 仅 `71.5 KiB` gzip** [已测]，**桌面全功能 WASM（密码学 + `ruzstd` 编解码 + Layer 1 格式化器）仅 `260.4 KiB` gzip** [已测]，远低于 `< 350 KiB` 目标。据此将 **`ADR-01` 升级为 `Accepted`**，并将 `docs/eval-framework.md` §10.1 标注实测参考基线。
  2. **Argon2id 参数候选**：Linux WebKit（JavaScriptCore）与 Chromium（V8）实测确认 `(65536, 3, 1)` 峰值线性内存仅 `65.19 MiB` [已测]、WebKit 中位耗时 `433 ms` [已测]，`(47104, 2, 1)` / `(65536, 3, 1)` 均为 `VaultHeaderV1` 强候选；**最终唯一三元组待在真机 iPhone Safari / PWA 打开 `bench.html` 实测确认**（`ADR-06` 保持 `Proposed`）。
- **复现路径**：[`spikes/s0-3-wasm-argon2/`](../../spikes/s0-3-wasm-argon2/)（`./measure.sh`、`cargo test --features comp-ruzstd-rw,comp-zstd-c`、`python3 run_browser_bench.py`、`bench.html`）。

---

## 1. `wasm32-unknown-unknown` 体积实测基线（`rustc 1.100.0` + `opt-level="z"` + `lto=true` + `wasm-opt 108 -Oz` + `gzip -9`）

| 构建配置 | 原始 `.wasm` | `wasm-opt -Oz` | `gzip -9` | 说明 |
| --- | ---: | ---: | ---: | --- |
| `1-crypto-only`（XChaCha20-Poly1305 + Argon2id + HKDF/SHA2 + BLAKE3 pure + X25519 无预计算表 + `rmp-serde` + `zeroize`） | 129.6 KiB | 114.2 KiB | **47.3 KiB** [已测] | 纯密码学底座 |
| `2-crypto-x25519-precomp`（开启 `x25519-dalek/precomputed-tables`） | 159.1 KiB | 143.9 KiB | **75.1 KiB** [已测] | 仅恢复封装低频调用，**建议关闭以省 27.8 KiB** |
| `3-mobile-ruzstd-decode`（**手机只读 PWA 目标配置**：密码学 + `ruzstd` 解压） | 206.6 KiB | 180.5 KiB | **71.5 KiB** [已测] | 仅占 350 KiB 预算的 20.4% |
| `4-desktop-ruzstd-rw`（密码学 + `ruzstd` 纯 Rust 压缩与解压） | 252.5 KiB | 222.6 KiB | **88.4 KiB** [已测] | 零 C 工具链，双向帧与 C `zstd` 完全兼容 |
| `5-desktop-miniz-rw`（对照：`miniz_oxide` Deflate） | 165.1 KiB | 146.9 KiB | **61.6 KiB** [已测] | 仅作对比；`ruzstd` 仅多 26.8 KiB 且免改 `zstd` 线格式 |
| `6-desktop-ruzstd-layer1`（**桌面全功能**：`4` + `serde_json` + `toml` + `serde_yaml_ng` + `sqlformat` + `quick-xml`） | 699.8 KiB | 624.3 KiB | **260.4 KiB** [已测] | 低于 `< 350 KiB` 目标，余量 ~90 KiB 给 `wasm-bindgen` 与 `WasmSyncEngine` |
| `7-desktop-zstd-c`（C 绑定 `zstd 0.14.5` / `zstd-sys`） | 580.2 KiB | 490.4 KiB | **167.6 KiB** [已测] | 比纯 Rust `ruzstd` 胖 **+79.2 KiB** 且依赖 C 交叉编译，**否决** |

- **帧互通验证**：`cargo test --features comp-ruzstd-rw,comp-zstd-c` 通过（空串、短文本、500x JSON、200x CJK/Emoji 全部验证 `zstd::encode_all` → `ruzstd::StreamingDecoder` 与 `ruzstd::encoding::compress_to_vec` → `zstd::decode_all` 字节级无损往返）。
- **依赖选型拍板**：
  - 桌面原生核心（`mynote-core` native）可使用 `zstd` 或 `ruzstd`；
  - `mynote-wasm` 一律采用 **纯 Rust `ruzstd`**（手机构建仅编解码端、桌面构建含编码端）并**禁用 `x25519-dalek/precomputed-tables`**；保留 `MNB1` 的 `zstd` 线格式不变。

---

## 2. Argon2id WASM 耗时与线性内存实测（3 次中位数，`4-desktop-ruzstd-rw.opt.wasm`）

| 参数 `(m_kib, t, p)` | 内存 `m` | Chromium 159 (V8, Linux x64) | WebKit 27.2 (JSC, Linux x64) | 峰值 WASM 线性内存 | iPhone Safari / PWA 真机 |
| --- | ---: | ---: | ---: | ---: | :---: |
| `(19456, 2, 1)`（OWASP 下限） | 19 MiB | 74.7 ms [已测] | 85 ms [已测] | 20.19 MiB [已测] | `___ ms` `[待真机]` |
| `(19456, 3, 1)` | 19 MiB | 101.2 ms [已测] | 122 ms [已测] | 20.19 MiB [已测] | `___ ms` `[待真机]` |
| `(32768, 2, 1)` | 32 MiB | 125.3 ms [已测] | 153 ms [已测] | 33.19 MiB [已测] | `___ ms` `[待真机]` |
| `(32768, 3, 1)` | 32 MiB | 171.2 ms [已测] | 214 ms [已测] | 33.19 MiB [已测] | `___ ms` `[待真机]` |
| `(47104, 2, 1)`（OWASP 46 MiB） | 46 MiB | 180.2 ms [已测] | 209 ms [已测] | 47.19 MiB [已测] | `___ ms` `[待真机]` |
| `(65536, 2, 1)` | 64 MiB | 258.8 ms [已测] | 335 ms [已测] | 65.19 MiB [已测] | `___ ms` `[待真机]` |
| `(65536, 3, 1)`（当前暂定值） | 64 MiB | 367.5 ms [已测] | 433 ms [已测] | 65.19 MiB [已测] | `___ ms` `[待真机]` |

- **真机完成步骤**：在局域网执行 `python3 -m http.server 8080`（目录 `spikes/s0-3-wasm-argon2/`），用 iPhone Safari 及添加到主屏幕的 PWA 打开 `http://<mac-ip>:8080/bench.html` 点击 **Run Argon2id Matrix**，挑出单次耗时落在 `1–2 s` 且无内存闪退的最高强度组合，回填上表并固化至 `VaultHeaderV1` 默认值。
