#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"

OUT_DIR="$ROOT/build"
VERSION=""
ARCH="$(uname -m)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --arch)
      ARCH="$2"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--version X.Y.Z] [--out DIR] [--arch arm64|x86_64]" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(grep -m1 '^version = "' "$REPO_ROOT/Cargo.toml" | sed -E 's/^version = "([^"]+)"/\1/')"
fi
if [[ -z "$VERSION" ]]; then
  echo "ERROR: could not determine version from Cargo.toml or --version" >&2
  exit 1
fi

case "$ARCH" in
  arm64|aarch64)
    SWIFT_TARGET="arm64-apple-macosx14.0"
    ;;
  x86_64)
    SWIFT_TARGET="x86_64-apple-macosx14.0"
    ;;
  *)
    echo "ERROR: unsupported arch '$ARCH' (expected arm64 or x86_64)" >&2
    exit 2
    ;;
esac

APP_DIR="$OUT_DIR/MyNote.app"
CONTENTS="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RES_DIR="$CONTENTS/Resources"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RES_DIR"

START_NS=$(python3 -c 'import time; print(time.monotonic_ns())')

swiftc \
  -O \
  -target "$SWIFT_TARGET" \
  -framework AppKit \
  -framework WebKit \
  -framework Carbon \
  -framework CryptoKit \
  -o "$MACOS_DIR/MyNote" \
  "$ROOT/Sources/MyNoteShell/DaemonClient.swift" \
  "$ROOT/Sources/MyNoteShell/HotKeyManager.swift" \
  "$ROOT/Sources/MyNoteShell/AppDelegate.swift" \
  "$ROOT/Sources/MyNoteShell/SelfTest.swift" \
  "$ROOT/Sources/MyNoteShell/main.swift"

END_NS=$(python3 -c 'import time; print(time.monotonic_ns())')
COMPILE_MS=$(( (END_NS - START_NS) / 1000000 ))

# Generate deterministic macOS .icns matching web/public-pwa/icon.svg (zero external tools)
ICONSET="$OUT_DIR/AppIcon.iconset"
rm -rf "$ICONSET"
mkdir -p "$ICONSET"
swift - "$ICONSET" <<'SWIFT'
import AppKit
import Foundation

let outDir = CommandLine.arguments[1]
let specs: [(Int, String)] = [
    (16, "icon_16x16.png"),
    (32, "icon_16x16@2x.png"),
    (32, "icon_32x32.png"),
    (64, "icon_32x32@2x.png"),
    (128, "icon_128x128.png"),
    (256, "icon_128x128@2x.png"),
    (256, "icon_256x256.png"),
    (512, "icon_256x256@2x.png"),
    (512, "icon_512x512.png"),
    (1024, "icon_512x512@2x.png"),
]

for (px, name) in specs {
    let s = CGFloat(px)
    let scale = s / 128.0
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: px,
        pixelsHigh: px,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else { continue }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

    let ctx = NSGraphicsContext.current!.cgContext
    ctx.translateBy(x: 0, y: s)
    ctx.scaleBy(x: scale, y: -scale)

    NSColor(calibratedRed: 0x11/255.0, green: 0x11/255.0, blue: 0x10/255.0, alpha: 1).setFill()
    NSBezierPath(roundedRect: NSRect(x: 0, y: 0, width: 128, height: 128), xRadius: 28, yRadius: 28).fill()

    NSColor(calibratedRed: 0x1C/255.0, green: 0x1B/255.0, blue: 0x19/255.0, alpha: 1).setFill()
    NSColor(calibratedRed: 0x7A/255.0, green: 0xA8/255.0, blue: 0xFF/255.0, alpha: 1).setStroke()
    let card = NSBezierPath(roundedRect: NSRect(x: 22, y: 24, width: 84, height: 80), xRadius: 14, yRadius: 14)
    card.lineWidth = 5
    card.fill()
    card.stroke()

    let lines: [(CGFloat, CGFloat, NSColor)] = [
        (48, 90, NSColor(calibratedRed: 0xEC/255.0, green: 0xEA/255.0, blue: 0xE4/255.0, alpha: 1)),
        (66, 78, NSColor(calibratedRed: 0xA1/255.0, green: 0x9C/255.0, blue: 0x92/255.0, alpha: 1)),
        (84, 66, NSColor(calibratedRed: 0x7A/255.0, green: 0xA8/255.0, blue: 0xFF/255.0, alpha: 1)),
    ]
    for (y, x2, color) in lines {
        color.setStroke()
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 38, y: y))
        p.line(to: NSPoint(x: x2, y: y))
        p.lineWidth = 6
        p.lineCapStyle = .round
        p.stroke()
    }
    NSGraphicsContext.restoreGraphicsState()

    if let png = rep.representation(using: .png, properties: [:]) {
        try png.write(to: URL(fileURLWithPath: outDir).appendingPathComponent(name))
    }
}
SWIFT

iconutil -c icns "$ICONSET" -o "$RES_DIR/AppIcon.icns"
rm -rf "$ICONSET"

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>MyNote</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>dev.mynote.macos-shell</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>my-note</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsLocalNetworking</key>
        <true/>
    </dict>
</dict>
</plist>
PLIST

# Ad-hoc sign so macOS validates bundle integrity cleanly
codesign --force --deep --sign - "$APP_DIR"
codesign --verify --deep --strict "$APP_DIR"

BIN_BYTES=$(stat -f%z "$MACOS_DIR/MyNote")
APP_KB=$(du -sk "$APP_DIR" | awk '{print $1}')
echo "Built: $APP_DIR (v${VERSION}, ${SWIFT_TARGET})"
echo "Compile time: ${COMPILE_MS} ms"
echo "Mach-O binary: ${BIN_BYTES} bytes"
echo "Total .app bundle: ${APP_KB} KiB"
