# S-Clip-4: Omarchy / Hyprland Wayland 图文剪贴板与只读监听共存 Spike（Issue #52）

独立技术验证脚手架（不纳入正式 Cargo Workspace），在真实 Omarchy（Arch + Hyprland + XWayland）环境下验证：

1. Hyprland 暴露的 Wayland data-control 协议（`ext_data_control_manager_v1` / `zwlr_data_control_manager_v1`）；
2. `wl-copy` 2.3.0 多 MIME 限制对比 `wl-clipboard-rs 0.9.5` `prepare_copy_multi` 多 MIME 写入（`image/png` / `text/plain` + `application/x-mynote-synced` + `x-kde-passwordManagerHint`）；
3. `wl-clipboard-rs::watch::Watcher` 严格只读观察者（零 `set_selection`）与 Omarchy 内置 `wl-paste --watch .../capture.sh` 并发共存，先检 offer MIME 列表跳过敏感/回环标记（零 pipe 读取）；
4. Wayland ↔ XWayland（`Xwayland :0`）双向文本与 `image/png` 粘贴互通且零剪贴板清空。

## 复现方式（在 Omarchy 主机）

```bash
export CARGO_TARGET_DIR=/tmp/s-clip-4-target
cargo test
cargo build --release
chmod +x run_omarchy_eval.sh
./run_omarchy_eval.sh /tmp/s-clip-4-target/release/s-clip-4-hyprland-wayland
```
