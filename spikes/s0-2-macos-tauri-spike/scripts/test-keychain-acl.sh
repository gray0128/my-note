#!/usr/bin/env bash
# S0-2 Experiment 2: Test macOS Keychain cross-binary code-signing ACL prompt behavior.
# Simulates Tauri .app (binary A) writing SMK and Homebrew CLI (binary B) reading SMK.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: This script must be run on macOS (Darwin)." >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
SERVICE="dev.mynote.s02-acl-spike"
ACCOUNT="smk_v1"

cat > "$WORK_DIR/writer.c" <<'EOF'
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    const char *svc = "dev.mynote.s02-acl-spike";
    const char *acc = "smk_v1";
    const char *secret = "0123456789abcdef0123456789abcdef";
    SecKeychainItemRef item = NULL;
    if (SecKeychainFindGenericPassword(NULL, strlen(svc), svc, strlen(acc), acc, NULL, NULL, &item) == errSecSuccess && item) {
        SecKeychainItemDelete(item);
        CFRelease(item);
    }
    OSStatus st = SecKeychainAddGenericPassword(NULL, strlen(svc), svc, strlen(acc), acc, strlen(secret), secret, NULL);
    printf("[writer] SecKeychainAddGenericPassword status=%d\n", (int)st);
    return st == errSecSuccess ? 0 : 1;
}
EOF

cat > "$WORK_DIR/reader.c" <<'EOF'
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    const char *svc = "dev.mynote.s02-acl-spike";
    const char *acc = "smk_v1";
    UInt32 len = 0;
    void *data = NULL;
    OSStatus st = SecKeychainFindGenericPassword(NULL, strlen(svc), svc, strlen(acc), acc, &len, &data, NULL);
    printf("[reader] SecKeychainFindGenericPassword status=%d len=%u\n", (int)st, (unsigned)len);
    if (data) SecKeychainItemFreeContent(NULL, data);
    return st == errSecSuccess ? 0 : 1;
}
EOF

clang -framework Security -framework CoreFoundation "$WORK_DIR/writer.c" -o "$WORK_DIR/sim-tauri-app"
clang -framework Security -framework CoreFoundation "$WORK_DIR/reader.c" -o "$WORK_DIR/sim-homebrew-cli"

# Ad-hoc sign with distinct bundle identifiers to mirror Tauri .app vs Homebrew CLI
codesign -f -s - -i "dev.mynote.tauri" "$WORK_DIR/sim-tauri-app"
codesign -f -s - -i "dev.mynote.cli" "$WORK_DIR/sim-homebrew-cli"

echo "Step 1: Writing SMK entry from simulated Tauri .app binary..."
"$WORK_DIR/sim-tauri-app"

echo "Step 2: Reading SAME SMK entry from simulated Homebrew CLI binary..."
echo ">>> OBSERVE: Does macOS pop up a Keychain password prompt here? <<<"
"$WORK_DIR/sim-homebrew-cli"

echo "Step 3: Re-signing CLI binary (simulating 'brew upgrade') and reading again..."
codesign -f -s - -i "dev.mynote.cli" "$WORK_DIR/sim-homebrew-cli"
echo ">>> OBSERVE: Does macOS pop up ANOTHER Keychain prompt after CLI rebuild? <<<"
"$WORK_DIR/sim-homebrew-cli"

echo "Cleanup: removing spike Keychain entry..."
security delete-generic-password -s "$SERVICE" -a "$ACCOUNT" >/dev/null 2>&1 || true
echo "Done! Record observations in docs/spikes/s0-2-macos-tauri-shell.md."
