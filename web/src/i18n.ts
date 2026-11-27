export type Locale = "en" | "zh-CN";

export const LOCALE_STORAGE_KEY = "mynote.locale";
const LEGACY_LOCALE_STORAGE_KEY = "mynote-locale";

const EN_MESSAGES = {
  // App / Chrome
  "app.title": "my-note",
  "pwa.title": "my-note — Mobile Read-Only",
  "topbar.buffers": "Buffers",
  "topbar.buffersNav": "Buffers",
  "topbar.newBlock": "New Block",
  "topbar.newBlockTitle": "New block (Cmd/Ctrl+Enter)",
  "topbar.find": "Find",
  "topbar.findTitle": "Find & replace across blocks (Cmd/Ctrl+F)",
  "topbar.vim": "Vim",
  "topbar.vimTitleOn": "Vim keybindings enabled — click to disable",
  "topbar.vimTitleOff": "Enable Vim keybindings",
  "topbar.trashCount": "Trash ({count})",
  "topbar.trashLabel": "Trash",
  "topbar.clipInbox": "Clipboard",
  "topbar.clipInboxTitle": "Cross-device Clipboard (100 items) ({shortcut})",
  "topbar.shortcuts": "Shortcuts",
  "topbar.shortcutsTitle": "Keyboard shortcuts ({shortcut})",
  "topbar.close": "Close",
  "lang.label": "Language",

  // Theme Menu
  "theme.triggerLabel": "Theme",
  "theme.groupLabel": "Appearance",
  "theme.systemLight": "System (Light)",
  "theme.systemDark": "System (Dark)",
  "theme.light": "Light",
  "theme.dark": "Dark",

  // Sync Status
  "sync.title": "Click to sync now",
  "sync.synced": "Synced",
  "sync.syncedTitle": "Synced — click to sync now",
  "sync.syncing": "Syncing…",
  "sync.offline": "Offline",
  "sync.offlinePending": "Offline ({count})",
  "sync.conflict": "Conflict",
  "sync.localOnly": "Local",
  "sync.localOnlyTitle": "Local only — click to check sync",
  "sync.sessionExpired": "Session Expired",
  "sync.daemonDisconnected": "Disconnected",
  "sync.toastStatus": "Sync: {state}",

  // Vault Status & Modals
  "vault.setup": "Setup Vault",
  "vault.setupTitle": "Initialize encrypted Vault passphrase",
  "vault.locked": "Vault",
  "vault.lockedTitle": "Vault locked — unlock or change password",
  "vault.unlocked": "Unlocked",
  "vault.unlockedTitle": "Vault unlocked in memory — click to lock or change password",
  "vault.badgeLocked": "Vault",
  "vault.badgeUnlocked": "Vault · Open",
  "vault.unlockAction": "Unlock",
  "vault.tabUnlock": "Unlock",
  "vault.tabChangePass": "Change Password",
  "vault.passLabel": "Vault password",
  "vault.currentPassLabel": "Current password",
  "vault.currentPassPlaceholder": "Enter current Vault password",
  "vault.newPassLabel": "New password",
  "vault.confirmPassLabel": "Confirm new password",
  "vault.showPass": "Show password",
  "vault.hidePass": "Hide password",
  "vault.changePassModalTitle": "Change Vault Password",
  "vault.changePassLockedNote":
    "Verify your current Vault password to set a new one. Keys are re-wrapped strictly in browser WASM memory; your 24-word recovery bundle stays unchanged.",
  "vault.updatingPass": "Updating password…",
  "vault.errCurrentRequired": "Enter your current Vault password",
  "vault.initTitle": "Initialize Vault",
  "vault.initNote":
    "Set a Vault passphrase. Your Vault key is wrapped by both Argon2id(passphrase) and your 24-word recovery public key, and stays strictly in browser WASM memory while unlocked.",
  "vault.newPassPlaceholder": "New Vault passphrase (min 8 chars)",
  "vault.confirmPassPlaceholder": "Confirm Vault passphrase",
  "vault.initSubmit": "Initialize & Unlock Vault",
  "vault.deriving": "Deriving Argon2id key…",
  "vault.unlockTitle": "Unlock Vault",
  "vault.unlockNote":
    "Keys stay strictly in browser WASM memory and auto-lock on tab switch or 5 min idle.",
  "vault.passPlaceholder": "Vault passphrase",
  "vault.unlockSubmit": "Unlock Vault",
  "vault.unlocking": "Unlocking…",
  "vault.forgotBtn": "Forgot? Use 24 Words",
  "vault.recoverTitle": "Recover Vault with 24-Word Bundle",
  "vault.recoverNote":
    "Enter your 24 recovery words to unseal the Vault locally and optionally set a new passphrase.",
  "vault.wordsPlaceholder": "24 BIP39 recovery words separated by spaces…",
  "vault.optionalNewPass": "Optional new Vault passphrase (min 8 chars)",
  "vault.back": "Back",
  "vault.recoverSubmit": "Recover & Unlock",
  "vault.unlockedModalTitle": "Vault Unlocked",
  "vault.unlockedModalNote":
    "Unlocked strictly in browser WASM memory. Local daemon never sees Vault keys or plaintext. Auto-locks on tab switch or 5 min idle.",
  "vault.lockNowBtn": "Lock Vault Now",
  "vault.changePassSubtitle": "Change Vault Passphrase",
  "vault.changeNewPassPlaceholder": "New passphrase (min 8 chars)",
  "vault.changeConfirmPlaceholder": "Confirm new passphrase",
  "vault.updatePassBtn": "Update Passphrase",
  "vault.toastLocked": "Vault locked — keys & plaintext cleared from memory",
  "vault.toastInitOk": "Vault initialized and unlocked",
  "vault.toastUnlocked": "Vault unlocked in browser memory",
  "vault.toastRecovered": "Vault recovered and unlocked",
  "vault.toastPassUpdated": "Vault passphrase updated",
  "vault.errMinLen": "Passphrase must be at least 8 characters",
  "vault.errNewMinLen": "New passphrase must be at least 8 characters",
  "vault.errMismatch": "Passphrases do not match",
  "vault.errNoRecoveryPk": "Recovery public key unavailable from local daemon",
  "vault.errLockedSave": "Vault is locked — unlock Vault to save changes",
  "vault.errMissingMnw1": "Missing key wrap material for Vault block",
  "vault.errUnlockToFormat": "Unlock Vault to format this block in browser WASM",
  "vault.errLocked": "Vault is locked",
  "vault.errUnlockToRekey": "Vault must be unlocked to rekey a locked block",
  "vault.toastRescuedAll": "Rescued {count} blocked Vault op(s) with fresh keys",
  "vault.toastRescuedPartial": "Rescued {rescued}/{total} blocked Vault op(s); {remaining} still pending",

  // Block Card & Editor
  "block.langAria": "Block language",
  "block.viewModeAria": "Block view mode",
  "block.modeSource": "Source",
  "block.modeSourceTitle": "Source view (Cmd/Ctrl+E)",
  "block.modePreview": "Preview",
  "block.modePreviewTitle": "Preview view (Cmd/Ctrl+E)",
  "block.modeSplit": "Split",
  "block.modeSplitTitle": "Split source & live preview",
  "block.format": "Format",
  "block.formatTitle": "Format block (Cmd/Ctrl+Shift+F)",
  "block.formatWasmTitle": "Format in browser WASM only (zero network)",
  "block.copy": "Copy",
  "block.copyTitle": "Copy entire block (Cmd/Ctrl+Shift+C)",
  "block.copyRich": "Copy Rich",
  "block.copyRichTitle": "Copy clean semantic HTML + plain text",
  "block.more": "More actions",
  "block.lock": "Lock",
  "block.lockTitle": "Move block into encrypted Vault",
  "block.toTier1": "Remove Vault Lock",
  "block.toTier1Title": "Move block out of Vault back to standard notes",
  "block.purgeHist": "Purge Old History",
  "block.purgeHistTitle": "Schedule older historical keys for shred (24h min grace)",
  "block.history": "History",
  "block.historyTitle": "View version history & revert",
  "block.historyLockedTitle": "Unlock Vault to inspect history",
  "block.moveUp": "Move up",
  "block.moveUpTitle": "Move block up ({shortcut})",
  "block.moveDown": "Move down",
  "block.moveDownTitle": "Move block down ({shortcut})",
  "block.prevBlockTitle": "Previous block ({shortcut})",
  "block.nextBlockTitle": "Next block ({shortcut})",
  "block.newBelow": "New block below",
  "block.newBelowTitle": "New block below (Cmd/Ctrl+Enter)",
  "block.addBelowStream": "Add block",
  "block.trash": "Trash",
  "block.trashTitle": "Move block to Trash",
  "block.dirtyUnsaved": "Unsaved",
  "block.dirtyConflict": "Conflict (draft kept)",
  "block.dirtySaveFailed": "Save failed",
  "block.lockedCard": "Vault locked · Unlock to view",
  "block.lockedConcurrentNote": "concurrent version waiting",
  "block.unreadableCard":
    "Content unavailable (missing key or decryption failed) — read-only until keys sync.",
  "block.emptyStream":
    "This buffer has no blocks yet. Press Cmd/Ctrl+Enter to start writing.",
  "block.toastMerged": "Merged versions cleanly",
  "block.toastHeadMismatch":
    "Concurrent update detected — your draft is preserved; choose Save Over or Reload",
  "block.toastCannotFormatUnreadable": "Cannot format an unreadable block",
  "block.toastResolveBeforeFormat": "Resolve concurrent versions before formatting",
  "block.toastFormattedWasm": "Formatted ({lang}) in WASM",
  "block.toastFormatted": "Formatted ({lang})",
  "block.toastCopied": "Copied block to clipboard",
  "block.toastCopiedRich": "Copied rich HTML + plain text",
  "block.toastClipboardUnavailable": "Clipboard permission unavailable",
  "block.toastMovedToTrash": "Moved block to Trash",
  "block.toastCannotDecryptSelected": "Selected version cannot be decrypted",
  "block.toastConflictResolvedT2": "Vault conflict resolved",
  "block.toastConflictResolved": "Conflict resolved to selected version",
  "block.toastResolveBeforeTaskToggle": "Resolve concurrent conflict before toggling tasks",

  // Conflicts & Mismatch
  "conflict.badge": "Conflict · {count} versions",
  "conflict.title": "{count} conflicting versions — pick a version or edit above to merge",
  "conflict.commitMerged": "Commit Merged Text",
  "conflict.displayed": "Shown",
  "conflict.otherDevice": "Other device",
  "conflict.keepVersion": "Keep version",
  "conflict.keepShown": "Keep shown",
  "conflict.useVersion": "Use this",
  "conflict.cannotKeepTitle": "Cannot keep an unreadable or sealed version",
  "conflict.sealed": "Locked in Vault",
  "conflict.unavailable": "Unavailable (missing key or decrypt failed)",
  "mismatch.notice": "Concurrent edit detected — your unsaved draft is preserved.",
  "mismatch.saveOver": "Save My Draft Over Latest",
  "mismatch.discardReload": "Discard & Reload",

  // Find & Replace
  "find.placeholder": "Find in buffer…",
  "find.replacePlaceholder": "Replace with…",
  "find.matches": "{count} matches",
  "find.prev": "Prev",
  "find.next": "Next",
  "find.replaceAll": "Replace All",
  "find.toastReplaced": "Replaced {count} occurrence(s)",

  // Buffer Modal
  "buffer.modalTitle": "Buffers",
  "buffer.filterPlaceholder": "Filter or create buffer…",
  "buffer.emptyFilter": "No matching buffers.",
  "buffer.current": "Current",
  "buffer.newPlaceholder": "New buffer name…",
  "buffer.create": "Create",
  "buffer.createInline": 'Create "{name}"',
  "buffer.blockCountOne": "1 block",
  "buffer.blockCount": "{count} blocks",
  "buffer.rename": "Rename",
  "buffer.renamePrompt": "New buffer name:",
  "buffer.hintNavigate": "Navigate",
  "buffer.hintOpen": "Open",
  "buffer.hintClose": "Close",

  // Lock / Downgrade Modals
  "lockModal.title": "Lock Block in Vault",
  "lockModal.note":
    "Content will be re-encrypted inside browser WASM with a new Vault key. The previous key will be scheduled for shred after a 24h grace period.",
  "lockModal.hintPlaceholder": 'Optional label (e.g. "Prod AWS root") — visible while locked',
  "lockModal.confirm": "Lock Block",
  "lockModal.toastLocked": "Block moved to Vault",
  "downgradeModal.title": "Remove Vault Lock",
  "downgradeModal.note":
    "Removing the Vault lock re-encrypts this block as a standard note accessible to CLI and local tools on this device.",
  "downgradeModal.shredOpt": "Also schedule previous Vault key for shred (24h min grace)",
  "downgradeModal.confirm": "Remove Lock",
  "downgradeModal.toastDowngraded": "Vault lock removed",
  "common.cancel": "Cancel",

  // History & Trash Drawers
  "history.title": "History",
  "history.titleWithBlock": "History · {lang}",
  "history.titleFallback": "History",
  "history.loading": "Loading history…",
  "history.apiUnavailable": "Block history API unavailable",
  "history.loadFailed": "Failed to load block history",
  "history.loadOpFailed": "Failed to load historical content",
  "history.missingTier2Blob": "Missing ciphertext or key wrap for historical Vault version",
  "history.missingTier2PredBlob": "Missing ciphertext or key wrap for predecessor version",
  "history.resolveBeforeRevert": "Resolve concurrent versions before reverting",
  "history.selectedUnavailable": "Selected version content is unavailable",
  "history.toastReverted": "Reverted block to selected version",
  "history.toastUndidActor": "Undid {actor} batch",
  "history.undoActor": "Undo {actor} batch",
  "history.noPredecessor": 'No earlier version outside "{actor}"',
  "history.predUnavailable": "Predecessor version is shredded or unavailable",
  "history.conflictHint": "Resolve concurrent versions before reverting.",
  "history.empty": "No history entries found.",
  "history.errorPrefix": "Error: {msg}",
  "history.vaultVersionTitle": "Vault version",
  "history.current": "Current",
  "history.shredded": "Shredded / Unavailable",
  "history.meta": "Metadata",
  "history.inspecting": "Inspecting",
  "history.diffInspect": "Diff & Inspect",
  "history.loadingOp": "Loading version content…",
  "history.diffTitle": "Selected version → Current",
  "history.revertBtn": "Revert to this version",
  "history.diffEmpty": "(empty)",
  "history.rawDetails": "Raw historical content",
  "history.opCreate": "Created",
  "history.opUpdate": "Edited",
  "history.opLock": "Locked",
  "history.opUnlock": "Unlocked",
  "history.opSetMeta": "Metadata",
  "history.opDelete": "Deleted",
  "history.opRestore": "Restored",
  "history.opResolve": "Merged",
  "history.actorHuman": "You",
  "history.justNow": "Just now",
  "history.minsAgo": "{count}m ago",
  "history.hoursAgo": "{count}h ago",
  "history.daysAgo": "{count}d ago",

  "trash.title": "Trash",
  "trash.empty": "Trash is empty.",
  "trash.confirmPending": "Confirm Pending ({count})",
  "trash.expediteAll": "Expedite All",
  "trash.expediteAllTitle": "Shorten all shred countdowns to 24h minimum grace",
  "trash.restore": "Restore",
  "trash.expedite": "Expedite",
  "trash.expediteTitle": "Shorten shred countdown to 24h minimum grace",
  "trash.lockedPreview": "Locked Vault block",
  "trash.stateScheduled": "Scheduled",
  "trash.stateExpedited": "Expedited",
  "trash.stateUnscheduled": "Recoverable",
  "trash.statePendingConfirm": "Needs confirmation",
  "trash.stateExecuted": "Shredded",
  "trash.shredEarliest": "Shred ≥ {time}",
  "trash.apiUnavailable": "Trash confirmation API unavailable",
  "trash.toastRestored": "Restored block from Trash",
  "trash.toastPurgeScheduled": "Current version rekeyed; old history keys scheduled for shred (≥24h)",
  "trash.toastActionConfirmed": "Confirmed shred schedule",

  "shred.titleExpedite": "Confirm Expedite Shred",
  "shred.titlePending": "Confirm Pending Batch Shred",
  "shred.titlePurge": "Confirm Purge Historical Versions",
  "shred.summaryAction": "Action: {action}",
  "shred.summaryBlocks": "Target blocks: {count}",
  "shred.summaryKeys": "Keys affected: {count}",
  "shred.summaryGrace": "Grace period: {hours}h (server enforces ≥ 24h minimum)",
  "shred.summaryEarliest": "Current earliest shred: {iso}",
  "shred.warn":
    "Once the server-enforced grace countdown expires, affected encryption keys are permanently erased and ciphertext becomes unreadable. You may still restore or cancel before execution.",
  "shred.confirmBtn": "Confirm Shred Schedule",

  // Alerts
  "alert.secretNudge":
    "Possible secret ({type}) pasted into a standard block — consider moving it into Vault.",
  "alert.lockBlock": "Lock Block",
  "alert.dismiss": "Dismiss",
  "alert.reviewTrash": "Review Trash",
  "alert.unlockRekey": "Unlock Vault to Rekey",
  "alert.keyMissing":
    "KEY_MISSING: Active block missing encryption key — run 'mynote sync pull' and do not delete data.",
  "alert.authRequired":
    "AUTH_REQUIRED: Local daemon session expired — run 'mynote open' to obtain a fresh login ticket.",
  "alert.deviceRevoked":
    "DEVICE_REVOKED: This device token was revoked on the relay — re-pair or re-bootstrap before syncing.",
  "alert.clockSkew":
    "CLOCK_SKEW: Remote clock skew detected ({details}). All versions preserved safely.",
  "alert.recoveryDrillDue":
    "RECOVERY_DRILL_DUE: Keyring rotated — run 'mynote recovery drill' to verify your 24-word bundle.",
  "alert.shredPendingConfirm":
    "SHRED_PENDING_CONFIRM: Batch/high-volume shred marks require explicit desktop UI confirmation before countdown starts.",
  "alert.needsVaultRekey":
    "NEEDS_VAULT_REKEY: Offline Vault edit(s) referenced a key pending shred — unlock Vault to re-encrypt under a fresh key automatically.",
  "alert.clipSecretBlocked":
    "CLIP_SECRET_BLOCKED: Auto-watch blocked a suspected secret ({details}) from uploading to clipboard history. Send manually with Ephemeral mode if needed.",

  // Markdown & Diagram Controls
  "md.blockedExtImg": "External image blocked:",
  "md.blockedImg": "Image blocked:",
  "md.copyCode": "Copy",
  "md.copyTsv": "TSV",
  "md.copyMd": "MD",
  "md.copied": "Copied",
  "md.copiedTsv": "Copied TSV",
  "md.copiedMd": "Copied MD",
  "md.copyFailed": "Copy failed",
  "diagram.controlsAria": "Diagram controls",
  "diagram.zoomIn": "Zoom in",
  "diagram.zoomOut": "Zoom out",
  "diagram.reset": "Reset",
  "diagram.copyMenu": "Copy",
  "diagram.copyPng": "Copy PNG",
  "diagram.copySvg": "Copy SVG",
  "diagram.copySource": "Copy Source",
  "diagram.pngCopied": "PNG copied",
  "diagram.svgCopied": "SVG copied",
  "diagram.syntaxError": "Diagram syntax error: {msg}",
  "diagram.syntaxFallback": "Diagram syntax error: unable to render Mermaid diagram",

  // Mobile Read-Only PWA
  "pwa.readOnlyPill": "READ-ONLY",
  "pwa.lockBtn": "Lock",
  "pwa.vaultBtn": "Vault",
  "pwa.keysBtn": "Keys",
  "pwa.keysTitle": "Refresh device keys",
  "pwa.searchPlaceholder": "Filter blocks in memory…",
  "pwa.onboardTitle": "Pair Read-Only Mobile Device",
  "pwa.onboardBody":
    "Run this command on your desktop, then paste or scan the pairing code below.",
  "pwa.onboardPrivacy": "Keys stay encrypted locally; plaintext is never written to storage.",
  "pwa.pairSubmit": "Pair Device",
  "pwa.scanQr": "Scan QR",
  "pwa.stopCamera": "Stop Camera",
  "pwa.qrUnavailable":
    "In-app QR camera scanning is unavailable in this browser — paste the pairing code directly above.",
  "pwa.qrDenied": "Camera permission denied — paste the pairing code directly above.",
  "pwa.emptyNoNotes": "No notes synced yet.",
  "pwa.emptyNoMatch": "No matching blocks in this buffer.",
  "pwa.unlockTitle": "Unlock Mobile Vault",
  "pwa.unlockNote":
    "Keys stay strictly in browser WASM memory (never written to storage) and auto-lock when you switch apps.",
  "pwa.unlockSubmit": "Unlock",
  "pwa.derivingKey": "Deriving key…",
  "pwa.noVaultConfigured": "No Vault configured yet — initialize Vault on desktop first",
  "pwa.toastVaultUnlocked": "Vault unlocked in memory (auto-locks on app switch)",
  "pwa.toastVaultLocked": "Vault locked — keys & plaintext wiped",
  "pwa.refreshKeysTitle": "Refresh Device Keys",
  "pwa.refreshKeysNote": "Run this command on your desktop and paste the refresh code:",
  "pwa.refreshKeysSubmit": "Refresh Keys",
  "pwa.footerLabel": "",
  "pwa.unpair": "Unpair device",
  "pwa.toastUnpaired": "Unpaired and cleared local cache",
  "pwa.swUpdate": "New app version available.",
  "pwa.swReload": "Update & Reload",
  "pwa.revoked":
    "DEVICE_REVOKED: This mobile device was revoked on the relay. Clear local cache and re-pair from desktop.",
  "pwa.resetRepair": "Reset & Re-Pair",
  "pwa.snatchWarning":
    "Pairing ticket missing, expired, or ALREADY CLAIMED! If you did not claim it, run 'mynote device ls' and 'mynote device revoke' on your desktop immediately.",
  "pwa.truncatedBanner":
    "Sync reached page limit with more updates on relay — tap Sync to continue.",
  "pwa.toastKeysRefreshed": "Keys refreshed — re-syncing…",
  "pwa.toastPairedSyncing": "Paired read-only device — syncing…",
  "pwa.toastSyncFailed": "Sync failed",
  "pwa.toastClipboardUnavailable": "Clipboard unavailable — tap & hold text to copy",
  "pwa.toastCopiedVault":
    "Copied Vault secret (Note: iOS/Universal Clipboard cannot be auto-cleared)",
  "pwa.toastCopiedRichVault":
    "Copied rich Vault secret (Note: iOS/Universal Clipboard cannot be auto-cleared)",
  "pwa.toastVaultSecretSuffix":
    "{msg} (Vault secret — iOS/Universal Clipboard cannot be auto-cleared)",
  "pwa.toastCopied": "Copied to clipboard",
  "pwa.statusIdle": "Sync",
  "pwa.statusSynced": "Synced",
  "pwa.statusPartial": "Partial #{seq}",
  "pwa.statusOffline": "Offline",
  "pwa.concurrentVersions": "{count} versions:",
  "pwa.versionDisplay": "Shown (#{num})",
  "pwa.versionOther": "#{num} · {dev}",
  "pwa.unreadable": "Content unavailable (missing key or awaiting key refresh).",

  // M4 Cross-Device Clipboard (Desktop & Mobile PWA)
  "clip.title": "Clipboard",
  "clip.count": "{count} / 100",
  "clip.empty": "No clipboard items yet. Send text or a bitmap image above.",
  "clip.placeholder": "Type or paste text / bitmap image to send…",
  "clip.send": "Send",
  "clip.sending": "Sending…",
  "clip.pickImage": "Image",
  "clip.pickImageTitle": "Send PNG, JPEG, WebP, or GIF image (≤ 10 MiB)",
  "clip.ephemeral": "Ephemeral (online desktop only, zero DB/R2)",
  "clip.ephemeralShort": "Ephemeral",
  "clip.undo": "Undo Overwrite",
  "clip.undoTitle": "Restore previous desktop clipboard content",
  "clip.clearAll": "Clear All",
  "clip.watchOff": "Auto-Watch: Off",
  "clip.watchOn": "Auto-Watch: On",
  "clip.watchEnableTitle": "Enable automatic capture of system clipboard copies (text & bitmap images)",
  "clip.watchDisableTitle": "Disable automatic system clipboard capture",
  "clip.watchPause": "Pause Watch",
  "clip.watchResume": "Resume Watch",
  "clip.watchPauseShort": "Pause",
  "clip.watchResumeShort": "Paused · Resume",
  "clip.watchPaused": "Watch Paused",
  "clip.watchActive": "Watch Active",
  "clip.watchModeInbox": "Inbox only",
  "clip.watchModeAutoApply": "Auto-apply",
  "clip.watchModeInboxTitle": "Incoming desktop auto-copies stay in the inbox without overwriting this device's clipboard — click to switch to Auto-apply",
  "clip.watchModeAutoApplyTitle": "Incoming desktop auto-copies write straight to this device's clipboard — click to switch to Inbox only",
  "clip.toastWatchEnabled": "Clipboard auto-watch enabled",
  "clip.toastWatchDisabled": "Clipboard auto-watch disabled",
  "clip.toastWatchModeInbox": "Receive mode: Inbox only",
  "clip.toastWatchModeAutoApply": "Receive mode: Auto-apply to clipboard",
  "alert.daemonUpdated": "Local mynote daemon updated to v{version} — refresh to load the latest UI.",
  "alert.refreshPage": "Refresh",
  "shortcuts.modalTitle": "Keyboard Shortcuts",
  "shortcuts.more": "Shortcuts",
  "shortcuts.groupBlocks": "Blocks & Editing",
  "shortcuts.groupNavigation": "Navigation & Panels",
  "shortcuts.groupVault": "Vault",
  "shortcuts.hintSwitchBlock": "Switch block",
  "shortcuts.hintClipboard": "Clipboard",
  "shortcuts.hintBuffers": "Buffers",
  "shortcuts.hintFind": "Find",
  "shortcuts.itemNewBlock": "New block below",
  "shortcuts.itemSwitchBlock": "Switch to previous / next block",
  "shortcuts.itemEdgeArrows": "Cross block boundary at first / last line",
  "shortcuts.itemMoveBlock": "Move current block up / down",
  "shortcuts.itemFocusLang": "Change block language",
  "shortcuts.itemToggleMarkdown": "Toggle Markdown source / preview",
  "shortcuts.itemFormatBlock": "Format current block",
  "shortcuts.itemCopyBlock": "Copy current block",
  "shortcuts.itemSwitchBuffer": "Switch or create buffer",
  "shortcuts.itemFind": "Find & replace across blocks",
  "shortcuts.itemToggleClip": "Toggle Clipboard drawer",
  "shortcuts.itemShowShortcuts": "Open keyboard shortcuts",
  "shortcuts.itemClose": "Close drawer or dialog",
  "shortcuts.itemLockVault": "Lock current block or open Vault",
  "clip.filterAll": "All",
  "clip.filterText": "Text",
  "clip.filterImage": "Images",
  "clip.kindText": "Text",
  "clip.kindImage": "Image",
  "clip.sourceAuto": "Auto",
  "clip.apply": "Copy",
  "clip.applyTitle": "Apply to system clipboard",
  "clip.preview": "Preview",
  "clip.saveAs": "Save As",
  "clip.promote": "To Note",
  "clip.promoteTitle": "Promote text item into a note block",
  "clip.delete": "Delete",
  "clip.previewModalTitle": "Clipboard Image Preview",
  "clip.loadingPreview": "Loading full image…",
  "clip.errSvgRejected":
    "SVG images (image/svg+xml) are blocked for XSS safety. Paste or send SVG source as plain text instead.",
  "clip.errUnsupportedMime":
    "Unsupported image format ({mime}). Only PNG, JPEG, WebP, and GIF bitmaps are allowed.",
  "clip.errTooLarge": "Clipboard item exceeds the 10 MiB size limit.",
  "clip.errEmpty": "Clipboard item is empty.",
  "clip.errEphemeralTooLarge": "Ephemeral text exceeds the 256 KiB limit.",
  "clip.errApiUnavailable": "Clipboard API is unavailable on this daemon.",
  "clip.errNoKey": "Clipboard encryption key (ClipKey) has not synced yet — tap Sync or push once from desktop.",
  "clip.errReadOnlyScope":
    "Paired with read-only scope. Re-pair with 'mynote device add --name iPhone --scope read+clip' to send or delete clips from mobile.",
  "clip.errIntegrity": "Clipboard blob integrity check (SHA-256) failed.",
  "clip.toastSent": "Sent to clipboard queue",
  "clip.toastSentEphemeral": "Sent ephemeral clip to {count} online desktop(s)",
  "clip.toastApplied": "Applied to desktop clipboard",
  "clip.toastPromoted": "Promoted clip to note block",
  "clip.toastUndone": "Restored previous desktop clipboard",
  "clip.toastDeleted": "Deleted clipboard item",
  "clip.toastCleared": "Cleared clipboard history",
  "clip.toastWatchPaused": "Clipboard auto-watch paused",
  "clip.toastWatchResumed": "Clipboard auto-watch resumed",
  "clip.toastImageCopied": "Copied PNG image to clipboard",
  "clip.toastShareSent": "Encrypted & sent shared item to clipboard",
  "pwa.tabNotes": "Notes",
  "pwa.tabClip": "Clipboard",
  "pwa.clipTextareaPlaceholder": "Tap & paste text here to send (zero iOS prompt)…",
  "pwa.clipCopyImage": "Copy PNG",
  "pwa.clipScopeReadClip": "READ + CLIP",
  "pwa.clipUnreadableItem": "Encrypted with rotated or unavailable ClipKey",
} as const;

export type MessageKey = keyof typeof EN_MESSAGES;

const ZH_CN_MESSAGES: Record<MessageKey, string> = {
  // App / Chrome
  "app.title": "my-note",
  "pwa.title": "my-note — 移动端只读",
  "topbar.buffers": "笔记本",
  "topbar.buffersNav": "笔记本列表",
  "topbar.newBlock": "新建块",
  "topbar.newBlockTitle": "插入新块 (Cmd/Ctrl+Enter)",
  "topbar.find": "查找",
  "topbar.findTitle": "跨块查找与替换 (Cmd/Ctrl+F)",
  "topbar.vim": "Vim",
  "topbar.vimTitleOn": "Vim 键位已开启 — 点击关闭",
  "topbar.vimTitleOff": "开启 Vim 键位",
  "topbar.trashCount": "回收站 ({count})",
  "topbar.trashLabel": "回收站",
  "topbar.clipInbox": "剪贴板",
  "topbar.clipInboxTitle": "跨端剪贴板（最近 100 条） ({shortcut})",
  "topbar.shortcuts": "快捷键",
  "topbar.shortcutsTitle": "快捷键一览 ({shortcut})",
  "topbar.close": "关闭",
  "lang.label": "语言",

  // Theme Menu
  "theme.triggerLabel": "外观主题",
  "theme.groupLabel": "外观",
  "theme.systemLight": "跟随系统（浅色）",
  "theme.systemDark": "跟随系统（深色）",
  "theme.light": "浅色",
  "theme.dark": "深色",

  // Sync Status
  "sync.title": "点击立即同步",
  "sync.synced": "已同步",
  "sync.syncedTitle": "已同步 — 点击立即同步",
  "sync.syncing": "同步中…",
  "sync.offline": "离线",
  "sync.offlinePending": "离线 ({count})",
  "sync.conflict": "冲突",
  "sync.localOnly": "本地",
  "sync.localOnlyTitle": "仅本地模式 — 点击检查同步",
  "sync.sessionExpired": "会话已过期",
  "sync.daemonDisconnected": "已断开",
  "sync.toastStatus": "同步状态：{state}",

  // Vault Status & Modals
  "vault.setup": "初始化保险库",
  "vault.setupTitle": "设置保险库口令",
  "vault.locked": "保险库",
  "vault.lockedTitle": "保险库已锁定 — 点击解锁或修改密码",
  "vault.unlocked": "已解锁",
  "vault.unlockedTitle": "保险库已在内存中解锁 — 点击锁定或修改密码",
  "vault.badgeLocked": "保险库",
  "vault.badgeUnlocked": "保险库 · 已解锁",
  "vault.unlockAction": "解锁",
  "vault.tabUnlock": "解锁",
  "vault.tabChangePass": "修改密码",
  "vault.passLabel": "保险库密码",
  "vault.currentPassLabel": "当前密码",
  "vault.currentPassPlaceholder": "输入当前保险库密码",
  "vault.newPassLabel": "新密码",
  "vault.confirmPassLabel": "确认新密码",
  "vault.showPass": "显示密码",
  "vault.hidePass": "隐藏密码",
  "vault.changePassModalTitle": "修改保险库密码",
  "vault.changePassLockedNote":
    "验证当前保险库密码后即可设置新密码。密钥仅在浏览器 WASM 内存中重新封装，24 词恢复包保持不变。",
  "vault.updatingPass": "正在更新密码…",
  "vault.errCurrentRequired": "请输入当前保险库密码",
  "vault.initTitle": "初始化保险库",
  "vault.initNote":
    "设置保险库口令。密钥同时由 Argon2id（口令）与 24 词恢复公钥封装，解锁期间仅驻留浏览器 WASM 内存。",
  "vault.newPassPlaceholder": "新保险库密码（至少 8 位）",
  "vault.confirmPassPlaceholder": "确认保险库密码",
  "vault.initSubmit": "初始化并解锁",
  "vault.deriving": "正在派生 Argon2id 密钥…",
  "vault.unlockTitle": "解锁保险库",
  "vault.unlockNote": "密钥仅在浏览器 WASM 内存中解密，切换标签页或空闲 5 分钟后自动清零。",
  "vault.passPlaceholder": "输入保险库密码",
  "vault.unlockSubmit": "解锁保险库",
  "vault.unlocking": "正在解锁…",
  "vault.forgotBtn": "忘记密码？用 24 词恢复",
  "vault.recoverTitle": "使用 24 词恢复包解封保险库",
  "vault.recoverNote": "输入 24 个恢复助记词在本地解封保险库，并可选择重置密码。",
  "vault.wordsPlaceholder": "输入以空格分隔的 24 个 BIP39 恢复词…",
  "vault.optionalNewPass": "可选：设置新保险库密码（至少 8 位）",
  "vault.back": "返回",
  "vault.recoverSubmit": "恢复并解锁",
  "vault.unlockedModalTitle": "保险库已解锁",
  "vault.unlockedModalNote":
    "仅在浏览器 WASM 内存中解锁，本地守护进程永不接触密钥或明文。切后台或空闲 5 分钟自动锁定。",
  "vault.lockNowBtn": "立即锁定并清零内存",
  "vault.changePassSubtitle": "修改保险库密码",
  "vault.changeNewPassPlaceholder": "新密码（至少 8 位）",
  "vault.changeConfirmPlaceholder": "确认新密码",
  "vault.updatePassBtn": "更新密码",
  "vault.toastLocked": "保险库已锁定 — 密钥与明文已从内存擦除",
  "vault.toastInitOk": "保险库已初始化并在内存中解锁",
  "vault.toastUnlocked": "保险库已在浏览器内存中解锁",
  "vault.toastRecovered": "保险库已恢复并解锁",
  "vault.toastPassUpdated": "保险库密码已更新",
  "vault.errMinLen": "口令长度至少为 8 个字符",
  "vault.errNewMinLen": "新口令长度至少为 8 个字符",
  "vault.errMismatch": "两次输入的口令不一致",
  "vault.errNoRecoveryPk": "无法从本地守护进程获取恢复公钥",
  "vault.errLockedSave": "保险库已锁定 — 请解锁后再保存修改",
  "vault.errMissingMnw1": "缺少保险库块的密钥封装材料",
  "vault.errUnlockToFormat": "请解锁保险库以在浏览器 WASM 中格式化此块",
  "vault.errLocked": "保险库已锁定",
  "vault.errUnlockToRekey": "必须先解锁保险库才能轮换加密块密钥",
  "vault.toastRescuedAll": "已用新密钥挽救 {count} 条阻塞的保险库操作",
  "vault.toastRescuedPartial": "已挽救 {rescued}/{total} 条阻塞的保险库操作，仍有 {remaining} 条待处理",

  // Block Card & Editor
  "block.langAria": "块语言",
  "block.viewModeAria": "块视图模式",
  "block.modeSource": "源码",
  "block.modeSourceTitle": "源码视图 (Cmd/Ctrl+E)",
  "block.modePreview": "预览",
  "block.modePreviewTitle": "预览视图 (Cmd/Ctrl+E)",
  "block.modeSplit": "分栏",
  "block.modeSplitTitle": "源码与实时预览分栏",
  "block.format": "格式化",
  "block.formatTitle": "格式化当前块 (Cmd/Ctrl+Shift+F)",
  "block.formatWasmTitle": "仅在浏览器 WASM 内存中格式化（零网络外发）",
  "block.copy": "复制",
  "block.copyTitle": "复制整块内容 (Cmd/Ctrl+Shift+C)",
  "block.copyRich": "复制富文本",
  "block.copyRichTitle": "复制纯净语义 HTML + 纯文本",
  "block.more": "更多操作",
  "block.lock": "移入保险库",
  "block.lockTitle": "将块加密移入保险库",
  "block.toTier1": "移出保险库",
  "block.toTier1Title": "解除保险库锁定并转回普通块",
  "block.purgeHist": "清理旧历史",
  "block.purgeHistTitle": "安排历史旧密钥进入加密碎纸宽限期（至少 24 小时）",
  "block.history": "版本历史",
  "block.historyTitle": "查看版本历史与回退",
  "block.historyLockedTitle": "解锁保险库后查看历史",
  "block.moveUp": "上移",
  "block.moveUpTitle": "上移当前块 ({shortcut})",
  "block.moveDown": "下移",
  "block.moveDownTitle": "下移当前块 ({shortcut})",
  "block.prevBlockTitle": "切换到上一个块 ({shortcut})",
  "block.nextBlockTitle": "切换到下一个块 ({shortcut})",
  "block.newBelow": "在下方新建块",
  "block.newBelowTitle": "在下方新建块 (Cmd/Ctrl+Enter)",
  "block.addBelowStream": "添加块",
  "block.trash": "移入回收站",
  "block.trashTitle": "移入回收站",
  "block.dirtyUnsaved": "未保存",
  "block.dirtyConflict": "冲突（草稿已保留）",
  "block.dirtySaveFailed": "保存失败",
  "block.lockedCard": "保险库已锁定 · 解锁后查看",
  "block.lockedConcurrentNote": "存在待合并并发版本",
  "block.unreadableCard": "内容暂不可读（缺少密钥或解密失败）— 在密钥同步前保持只读保护。",
  "block.emptyStream": "当前笔记本暂无内容块。按 Cmd/Ctrl+Enter 开始记录。",
  "block.toastMerged": "已合并并发版本",
  "block.toastHeadMismatch": "检测到远端并发修改 — 本地草稿已保留，请选择覆盖或重载",
  "block.toastCannotFormatUnreadable": "无法格式化不可读的内容块",
  "block.toastResolveBeforeFormat": "请先解决并发冲突后再格式化",
  "block.toastFormattedWasm": "已在 WASM 中格式化 ({lang})",
  "block.toastFormatted": "已格式化 ({lang})",
  "block.toastCopied": "已复制块内容到剪贴板",
  "block.toastCopiedRich": "已复制纯净 HTML 与纯文本",
  "block.toastClipboardUnavailable": "剪贴板权限不可用",
  "block.toastMovedToTrash": "已移入回收站",
  "block.toastCannotDecryptSelected": "无法解密所选版本",
  "block.toastConflictResolvedT2": "保险库并发冲突已解决",
  "block.toastConflictResolved": "已保留所选版本并解决冲突",
  "block.toastResolveBeforeTaskToggle": "请先解决并发冲突后再勾选任务",

  // Conflicts & Mismatch
  "conflict.badge": "冲突 · {count} 个版本",
  "conflict.title": "存在 {count} 个并发版本 — 选择保留版本或在上方编辑后合并",
  "conflict.commitMerged": "提交合并文本",
  "conflict.displayed": "当前显示",
  "conflict.otherDevice": "其他设备",
  "conflict.keepVersion": "保留此版本",
  "conflict.keepShown": "保留当前",
  "conflict.useVersion": "采用此版本",
  "conflict.cannotKeepTitle": "无法保留不可读或未解封版本",
  "conflict.sealed": "已在保险库中封存",
  "conflict.unavailable": "暂不可读（缺少密钥或解密失败）",
  "mismatch.notice": "检测到远端并发修改 — 本地草稿已完整保留。",
  "mismatch.saveOver": "用本地草稿覆盖最新",
  "mismatch.discardReload": "放弃草稿并重载",

  // Find & Replace
  "find.placeholder": "在当前笔记本中查找…",
  "find.replacePlaceholder": "替换为…",
  "find.matches": "{count} 处匹配",
  "find.prev": "上一个",
  "find.next": "下一个",
  "find.replaceAll": "全部替换",
  "find.toastReplaced": "已替换 {count} 处",

  // Buffer Modal
  "buffer.modalTitle": "笔记本",
  "buffer.filterPlaceholder": "筛选或新建笔记本…",
  "buffer.emptyFilter": "没有匹配的笔记本。",
  "buffer.current": "当前",
  "buffer.newPlaceholder": "新笔记本名称…",
  "buffer.create": "新建",
  "buffer.createInline": "新建「{name}」",
  "buffer.blockCountOne": "1 块",
  "buffer.blockCount": "{count} 块",
  "buffer.rename": "重命名",
  "buffer.renamePrompt": "输入新笔记本名称：",
  "buffer.hintNavigate": "选择",
  "buffer.hintOpen": "打开",
  "buffer.hintClose": "关闭",

  // Lock / Downgrade Modals
  "lockModal.title": "移入保险库",
  "lockModal.note":
    "正文将在浏览器 WASM 中使用全新保险库密钥重加密，旧密钥将进入至少 24 小时加密碎纸宽限期。",
  "lockModal.hintPlaceholder": '可选公开备注（如 "生产 AWS 根密钥"）— 锁定态下可见',
  "lockModal.confirm": "确认加密锁定",
  "lockModal.toastLocked": "块已移入保险库",
  "downgradeModal.title": "移出保险库",
  "downgradeModal.note": "解除保险库锁定后，本机 CLI 与本地工具将可读取此块。",
  "downgradeModal.shredOpt": "同时安排旧保险库密钥进入加密碎纸宽限期（至少 24 小时）",
  "downgradeModal.confirm": "确认移出",
  "downgradeModal.toastDowngraded": "已移出保险库",
  "common.cancel": "取消",

  // History & Trash Drawers
  "history.title": "版本历史",
  "history.titleWithBlock": "历史 · {lang}",
  "history.titleFallback": "版本历史",
  "history.loading": "正在加载历史…",
  "history.apiUnavailable": "历史记录接口不可用",
  "history.loadFailed": "加载块历史失败",
  "history.loadOpFailed": "加载历史版本内容失败",
  "history.missingTier2Blob": "历史保险库版本缺少密文或密钥封装",
  "history.missingTier2PredBlob": "前置版本缺少密文或密钥封装",
  "history.resolveBeforeRevert": "请先解决并发版本后再回退",
  "history.selectedUnavailable": "所选版本内容不可用",
  "history.toastReverted": "已将块回退到所选版本",
  "history.toastUndidActor": "已撤销 {actor} 批次改动",
  "history.undoActor": "撤销 {actor} 批次改动",
  "history.noPredecessor": "找不到早于「{actor}」的历史版本",
  "history.predUnavailable": "前置历史版本已碎纸或不可用",
  "history.conflictHint": "请先解决并发版本后再回退。",
  "history.empty": "暂无历史记录。",
  "history.errorPrefix": "错误：{msg}",
  "history.vaultVersionTitle": "保险库版本",
  "history.current": "当前",
  "history.shredded": "已碎纸",
  "history.meta": "属性",
  "history.inspecting": "查看中",
  "history.diffInspect": "对比查看",
  "history.loadingOp": "正在加载版本内容…",
  "history.diffTitle": "选中版本 → 当前",
  "history.revertBtn": "回退到此版本",
  "history.diffEmpty": "（空）",
  "history.rawDetails": "查看原始历史正文",
  "history.opCreate": "创建",
  "history.opUpdate": "编辑",
  "history.opLock": "加密",
  "history.opUnlock": "解密",
  "history.opSetMeta": "属性",
  "history.opDelete": "删除",
  "history.opRestore": "恢复",
  "history.opResolve": "合并",
  "history.actorHuman": "手动",
  "history.justNow": "刚刚",
  "history.minsAgo": "{count} 分钟前",
  "history.hoursAgo": "{count} 小时前",
  "history.daysAgo": "{count} 天前",

  "trash.title": "回收站",
  "trash.empty": "回收站为空。",
  "trash.confirmPending": "确认待碎纸 ({count})",
  "trash.expediteAll": "全部加速",
  "trash.expediteAllTitle": "将全部碎纸倒计时缩短至 24 小时最短宽限期",
  "trash.restore": "恢复",
  "trash.expedite": "加速碎纸",
  "trash.expediteTitle": "将碎纸倒计时缩短至 24 小时最短宽限期",
  "trash.lockedPreview": "已锁定保险库块",
  "trash.stateScheduled": "已排期",
  "trash.stateExpedited": "已加速",
  "trash.stateUnscheduled": "可恢复",
  "trash.statePendingConfirm": "待确认",
  "trash.stateExecuted": "已碎纸",
  "trash.shredEarliest": "最早碎纸 ≥ {time}",
  "trash.apiUnavailable": "回收站确认接口不可用",
  "trash.toastRestored": "已从回收站恢复块",
  "trash.toastPurgeScheduled": "当前版本已轮换密钥，旧历史密钥已进入碎纸宽限期（≥24h）",
  "trash.toastActionConfirmed": "已确认碎纸计划",

  "shred.titleExpedite": "确认加速加密碎纸",
  "shred.titlePending": "确认待处理批量碎纸",
  "shred.titlePurge": "确认清理历史版本",
  "shred.summaryAction": "操作：{action}",
  "shred.summaryBlocks": "目标块数：{count}",
  "shred.summaryKeys": "影响密钥数：{count}",
  "shred.summaryGrace": "宽限期：{hours} 小时（服务端强制至少 24 小时）",
  "shred.summaryEarliest": "当前最早碎纸时间：{iso}",
  "shred.warn":
    "服务端强制宽限期到期后，受影响的加密密钥将被永久擦除，对应密文不可再解密。执行前仍可随时恢复或取消。",
  "shred.confirmBtn": "确认碎纸计划",

  // Alerts
  "alert.secretNudge": "检测到疑似敏感凭据（{type}）粘贴到普通块 — 建议移入保险库加密保护。",
  "alert.lockBlock": "移入保险库",
  "alert.dismiss": "忽略",
  "alert.reviewTrash": "查看回收站",
  "alert.unlockRekey": "解锁保险库以重加密",
  "alert.keyMissing": "KEY_MISSING：活跃块缺少加密密钥 — 请运行 'mynote sync pull'，切勿删除数据。",
  "alert.authRequired": "AUTH_REQUIRED：本地守护进程会话已过期 — 请运行 'mynote open' 重新登录。",
  "alert.deviceRevoked": "DEVICE_REVOKED：当前设备令牌已在云端中继吊销 — 请重新配对后再同步。",
  "alert.clockSkew": "CLOCK_SKEW：检测到远端时钟偏差（{details}），所有版本均已安全保留。",
  "alert.recoveryDrillDue": "RECOVERY_DRILL_DUE：密钥环已轮换 — 请运行 'mynote recovery drill' 演练 24 词恢复包。",
  "alert.shredPendingConfirm": "SHRED_PENDING_CONFIRM：大批量碎纸标记需在桌面端显式确认后才开始倒计时。",
  "alert.needsVaultRekey":
    "NEEDS_VAULT_REKEY：离线保险库修改引用了待碎纸密钥 — 请解锁保险库以自动换钥重加密。",
  "alert.clipSecretBlocked":
    "CLIP_SECRET_BLOCKED：剪贴板自动监听拦截了疑似敏感凭据（{details}），未自动上传；如需发送请手动勾选「瞬态直推」。",

  // Markdown & Diagram Controls
  "md.blockedExtImg": "已拦截外链图片：",
  "md.blockedImg": "已拦截图片：",
  "md.copyCode": "复制",
  "md.copyTsv": "TSV",
  "md.copyMd": "MD",
  "md.copied": "已复制",
  "md.copiedTsv": "已复制 TSV",
  "md.copiedMd": "已复制 MD",
  "md.copyFailed": "复制失败",
  "diagram.controlsAria": "图表控制栏",
  "diagram.zoomIn": "放大",
  "diagram.zoomOut": "缩小",
  "diagram.reset": "重置",
  "diagram.copyMenu": "复制",
  "diagram.copyPng": "复制 PNG",
  "diagram.copySvg": "复制 SVG",
  "diagram.copySource": "复制源码",
  "diagram.pngCopied": "PNG 已复制",
  "diagram.svgCopied": "SVG 已复制",
  "diagram.syntaxError": "图表语法错误：{msg}",
  "diagram.syntaxFallback": "图表语法错误：无法渲染 Mermaid 图表",

  // Mobile Read-Only PWA
  "pwa.readOnlyPill": "只读",
  "pwa.lockBtn": "锁定",
  "pwa.vaultBtn": "保险库",
  "pwa.keysBtn": "密钥",
  "pwa.keysTitle": "刷新设备密钥",
  "pwa.searchPlaceholder": "在内存中筛选块…",
  "pwa.onboardTitle": "配对只读移动设备",
  "pwa.onboardBody": "在桌面端运行以下命令，然后将生成的配对码粘贴或扫码填入下方。",
  "pwa.onboardPrivacy": "密钥仅以密文保存在本地，正文永不落盘。",
  "pwa.pairSubmit": "配对设备",
  "pwa.scanQr": "扫码配对",
  "pwa.stopCamera": "关闭相机",
  "pwa.qrUnavailable": "当前浏览器不支持应用内扫码 — 请直接在上方粘贴配对码。",
  "pwa.qrDenied": "相机权限被拒绝 — 请直接在上方粘贴配对码。",
  "pwa.emptyNoNotes": "尚未同步任何笔记。",
  "pwa.emptyNoMatch": "当前笔记本中没有匹配的块。",
  "pwa.unlockTitle": "解锁移动端保险库",
  "pwa.unlockNote": "密钥仅在浏览器 WASM 内存中解密（永不落盘），切换应用时立即自动锁定并清零。",
  "pwa.unlockSubmit": "解锁",
  "pwa.derivingKey": "正在派生密钥…",
  "pwa.noVaultConfigured": "尚未配置保险库 — 请先在桌面端初始化保险库",
  "pwa.toastVaultUnlocked": "保险库已在内存中解锁（切后台自动锁定）",
  "pwa.toastVaultLocked": "保险库已锁定 — 密钥与明文已擦除",
  "pwa.refreshKeysTitle": "刷新设备密钥",
  "pwa.refreshKeysNote": "在桌面端运行以下命令并粘贴生成的刷新码：",
  "pwa.refreshKeysSubmit": "刷新密钥",
  "pwa.footerLabel": "",
  "pwa.unpair": "取消配对",
  "pwa.toastUnpaired": "已取消配对并清空本地缓存",
  "pwa.swUpdate": "发现新版本。",
  "pwa.swReload": "更新并重载",
  "pwa.revoked": "DEVICE_REVOKED：此移动设备已在云端中继吊销，请清除本地缓存并从桌面端重新配对。",
  "pwa.resetRepair": "重置并重新配对",
  "pwa.snatchWarning":
    "配对票据不存在、已过期或已被领取！如非本人操作，请立即在桌面端运行 'mynote device ls' 与 'mynote device revoke'。",
  "pwa.truncatedBanner": "同步已达分页上限，云端仍有更多更新 — 点击同步继续。",
  "pwa.toastKeysRefreshed": "密钥已刷新 — 正在重新同步…",
  "pwa.toastPairedSyncing": "已配对只读设备 — 正在同步…",
  "pwa.toastSyncFailed": "同步失败",
  "pwa.toastClipboardUnavailable": "剪贴板不可用 — 请长按正文手动复制",
  "pwa.toastCopiedVault": "已复制保险库正文（注：iOS / 通用剪贴板无法自动清除）",
  "pwa.toastCopiedRichVault": "已复制保险库富文本（注：iOS / 通用剪贴板无法自动清除）",
  "pwa.toastVaultSecretSuffix": "{msg}（保险库正文 — iOS / 通用剪贴板无法自动清除）",
  "pwa.toastCopied": "已复制到剪贴板",
  "pwa.statusIdle": "同步",
  "pwa.statusSynced": "已同步",
  "pwa.statusPartial": "部分同步 #{seq}",
  "pwa.statusOffline": "离线",
  "pwa.concurrentVersions": "{count} 个版本：",
  "pwa.versionDisplay": "当前 (#{num})",
  "pwa.versionOther": "#{num} · {dev}",
  "pwa.unreadable": "内容暂不可用（缺少密钥或等待密钥刷新）。",

  // M4 Cross-Device Clipboard (Desktop & Mobile PWA)
  "clip.title": "剪贴板",
  "clip.count": "{count} / 100",
  "clip.empty": "暂无剪贴板条目。在上方输入文本或选择位图图片发送。",
  "clip.placeholder": "输入或粘贴文本 / 位图图片以跨端发送…",
  "clip.send": "发送",
  "clip.sending": "发送中…",
  "clip.pickImage": "图片",
  "clip.pickImageTitle": "发送 PNG、JPEG、WebP 或 GIF 图片（≤ 10 MiB）",
  "clip.ephemeral": "瞬态直推（仅在线桌面，零写库零 R2）",
  "clip.ephemeralShort": "瞬态",
  "clip.undo": "撤销覆写",
  "clip.undoTitle": "恢复上次覆写前的桌面剪贴板内容",
  "clip.clearAll": "清空全部",
  "clip.watchOff": "自动监听：关",
  "clip.watchOn": "自动监听：开",
  "clip.watchEnableTitle": "开启后台自动捕获本机复制的文本与位图图片",
  "clip.watchDisableTitle": "关闭后台自动捕获系统剪贴板",
  "clip.watchPause": "暂停监听",
  "clip.watchResume": "恢复监听",
  "clip.watchPauseShort": "暂停",
  "clip.watchResumeShort": "已暂停 · 恢复",
  "clip.watchPaused": "监听已暂停",
  "clip.watchActive": "监听运行中",
  "clip.watchModeInbox": "仅清单",
  "clip.watchModeAutoApply": "自动写入",
  "clip.watchModeInboxTitle": "对端自动复制仅收入清单，不覆盖本机当前剪贴板 — 点击切换为自动写入",
  "clip.watchModeAutoApplyTitle": "对端自动复制直接写入本机系统剪贴板 — 点击切换为仅收入清单",
  "clip.toastWatchEnabled": "已开启剪贴板自动监听",
  "clip.toastWatchDisabled": "已关闭剪贴板自动监听",
  "clip.toastWatchModeInbox": "接收模式已切换为：仅收入清单",
  "clip.toastWatchModeAutoApply": "接收模式已切换为：自动写入剪贴板",
  "alert.daemonUpdated": "本地 mynote 服务已升级至 v{version} — 刷新页面以加载新版界面。",
  "alert.refreshPage": "刷新页面",
  "shortcuts.modalTitle": "快捷键一览",
  "shortcuts.more": "快捷键",
  "shortcuts.groupBlocks": "块与编辑",
  "shortcuts.groupNavigation": "导航与面板",
  "shortcuts.groupVault": "保险库",
  "shortcuts.hintSwitchBlock": "切换块",
  "shortcuts.hintClipboard": "剪贴板",
  "shortcuts.hintBuffers": "笔记本",
  "shortcuts.hintFind": "查找",
  "shortcuts.itemNewBlock": "在下方新建块",
  "shortcuts.itemSwitchBlock": "切换到上 / 下一个块",
  "shortcuts.itemEdgeArrows": "在首行 / 末行跨块移动光标",
  "shortcuts.itemMoveBlock": "上移 / 下移当前块",
  "shortcuts.itemFocusLang": "切换当前块语言",
  "shortcuts.itemToggleMarkdown": "切换 Markdown 源码 / 预览",
  "shortcuts.itemFormatBlock": "格式化当前块",
  "shortcuts.itemCopyBlock": "复制当前块",
  "shortcuts.itemSwitchBuffer": "切换或新建笔记本",
  "shortcuts.itemFind": "跨块查找与替换",
  "shortcuts.itemToggleClip": "打开 / 关闭剪贴板",
  "shortcuts.itemShowShortcuts": "打开快捷键一览",
  "shortcuts.itemClose": "关闭抽屉或弹窗",
  "shortcuts.itemLockVault": "锁定当前块或打开保险库",
  "clip.filterAll": "全部",
  "clip.filterText": "文本",
  "clip.filterImage": "图片",
  "clip.kindText": "文本",
  "clip.kindImage": "图片",
  "clip.sourceAuto": "自动",
  "clip.apply": "复制",
  "clip.applyTitle": "写入本机系统剪贴板",
  "clip.preview": "大图",
  "clip.saveAs": "另存为",
  "clip.promote": "转为笔记",
  "clip.promoteTitle": "将文本条目转存为正式笔记块",
  "clip.delete": "删除",
  "clip.previewModalTitle": "剪贴板原图预览",
  "clip.loadingPreview": "正在加载原图…",
  "clip.errSvgRejected": "出于防 XSS 安全要求，禁止将 SVG（image/svg+xml）作为图片发送；请以纯文本同步 SVG 源码。",
  "clip.errUnsupportedMime": "不支持的图片格式（{mime}），仅允许 PNG、JPEG、WebP、GIF 位图。",
  "clip.errTooLarge": "剪贴板条目超过 10 MiB 上限。",
  "clip.errEmpty": "剪贴板内容为空。",
  "clip.errEphemeralTooLarge": "瞬态直推文本超过 256 KiB 上限。",
  "clip.errApiUnavailable": "当前守护进程未提供剪贴板接口。",
  "clip.errNoKey": "尚未同步剪贴板密钥（ClipKey）— 请点击同步或在桌面发送一次剪贴板。",
  "clip.errReadOnlyScope":
    "当前为只读权限。如需从手机发送或删除剪贴板，请在桌面执行 'mynote device add --name iPhone --scope read+clip' 重新配对。",
  "clip.errIntegrity": "剪贴板大对象完整性校验（SHA-256）失败。",
  "clip.toastSent": "已发送到跨端剪贴板",
  "clip.toastSentEphemeral": "已瞬态直推至 {count} 台在线桌面",
  "clip.toastApplied": "已写入桌面系统剪贴板",
  "clip.toastPromoted": "已转存为笔记块",
  "clip.toastUndone": "已恢复上一条桌面剪贴板",
  "clip.toastDeleted": "已删除剪贴板条目",
  "clip.toastCleared": "已清空剪贴板历史",
  "clip.toastWatchPaused": "已暂停剪贴板自动监听",
  "clip.toastWatchResumed": "已恢复剪贴板自动监听",
  "clip.toastImageCopied": "已复制 PNG 图片到剪贴板",
  "clip.toastShareSent": "已加密并发送分享内容到剪贴板",
  "pwa.tabNotes": "笔记",
  "pwa.tabClip": "剪贴板",
  "pwa.clipTextareaPlaceholder": "轻点并粘贴文本直接发送（免 iOS 粘贴弹窗）…",
  "pwa.clipCopyImage": "复制 PNG",
  "pwa.clipScopeReadClip": "只读笔记 + 剪贴板",
  "pwa.clipUnreadableItem": "密钥已轮换或暂不可解密",
};

const CATALOG: Readonly<Record<Locale, Readonly<Record<MessageKey, string>>>> = {
  en: EN_MESSAGES,
  "zh-CN": ZH_CN_MESSAGES,
};

type LocaleListener = (locale: Locale) => void;

const listeners = new Set<LocaleListener>();
let memoryLocale: Locale | null = null;
let storageListenerBound = false;

function parseStoredLocale(raw: unknown): Locale | null {
  if (raw === "zh-CN" || raw === "en") return raw;
  return null;
}

function detectNavigatorLocale(): Locale {
  if (typeof navigator !== "undefined" && typeof navigator.language === "string") {
    if (navigator.language.toLowerCase().startsWith("zh")) {
      return "zh-CN";
    }
  }
  return "en";
}

function getSafeLocalStorage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    const store = window.localStorage;
    if (
      store &&
      typeof store.getItem === "function" &&
      typeof store.setItem === "function" &&
      typeof store.removeItem === "function"
    ) {
      return store;
    }
  } catch {
    // Storage access blocked
  }
  return null;
}

function readLocale(): Locale {
  const store = getSafeLocalStorage();
  if (store) {
    try {
      const stored =
        parseStoredLocale(store.getItem(LOCALE_STORAGE_KEY)) ??
        parseStoredLocale(store.getItem(LEGACY_LOCALE_STORAGE_KEY));
      if (stored) return stored;
      return detectNavigatorLocale();
    } catch {
      // Fall back to in-memory preference
    }
  }
  return memoryLocale ?? detectNavigatorLocale();
}

function applyLocaleToDocument(locale: Locale, titleKey?: "app.title" | "pwa.title"): void {
  if (typeof document === "undefined") return;
  document.documentElement.lang = locale;
  if (titleKey) {
    document.title = CATALOG[locale][titleKey];
  }
}

const onWindowStorage = (ev: StorageEvent): void => {
  if (ev.key !== null && ev.key !== LOCALE_STORAGE_KEY && ev.key !== LEGACY_LOCALE_STORAGE_KEY) {
    return;
  }
  const next = readLocale();
  memoryLocale = next;
  applyLocaleToDocument(next);
  for (const fn of [...listeners]) {
    fn(next);
  }
};

function ensureStorageListener(): void {
  if (typeof window === "undefined" || storageListenerBound) return;
  window.addEventListener("storage", onWindowStorage);
  storageListenerBound = true;
}

export function getLocale(): Locale {
  ensureStorageListener();
  return readLocale();
}

export function syncDocumentLocale(titleKey?: "app.title" | "pwa.title"): Locale {
  const current = getLocale();
  applyLocaleToDocument(current, titleKey);
  return current;
}

export function setLocale(next: Locale): Locale {
  ensureStorageListener();
  memoryLocale = next;
  const store = getSafeLocalStorage();
  if (store) {
    try {
      store.setItem(LOCALE_STORAGE_KEY, next);
    } catch {
      // Storage blocked: keep in-memory locale
    }
  }
  applyLocaleToDocument(next);
  for (const fn of [...listeners]) {
    fn(next);
  }
  return next;
}

export function toggleLocale(): Locale {
  const next: Locale = getLocale() === "zh-CN" ? "en" : "zh-CN";
  return setLocale(next);
}

export function subscribeLocale(fn: LocaleListener): () => void {
  ensureStorageListener();
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export function t(key: MessageKey, params?: Readonly<Record<string, string | number>>): string {
  const locale = getLocale();
  const template = CATALOG[locale][key];
  if (!params) return template;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name: string) => {
    if (Object.prototype.hasOwnProperty.call(params, name)) {
      return String(params[name]);
    }
    return match;
  });
}

/** Human-readable device label from internal IDs like `dev_macmini0001` or `dev_omarchy0001`. */
export function formatDeviceName(deviceId: string): string {
  const raw = deviceId.trim();
  if (!raw) return "";
  const stripped = raw.replace(/^dev_/i, "");
  const withoutPad = stripped.replace(/(?:0+[0-9a-f]{1,4}|[0-9]{4,})$/i, "");
  const clean = (withoutPad.length >= 2 ? withoutPad : stripped).replace(/[_-]+$/, "");
  return clean || raw.slice(0, 12);
}

export function formatOpTypeLabel(opType: string): string {
  switch (opType.toUpperCase()) {
    case "CREATE":
      return t("history.opCreate");
    case "UPDATE":
      return t("history.opUpdate");
    case "LOCK":
      return t("history.opLock");
    case "UNLOCK":
      return t("history.opUnlock");
    case "SET_META":
      return t("history.opSetMeta");
    case "DELETE":
      return t("history.opDelete");
    case "RESTORE":
      return t("history.opRestore");
    case "RESOLVE":
      return t("history.opResolve");
    default:
      return opType;
  }
}

export function formatActorLabel(actor: string): string {
  if (!actor || actor === "human") {
    return t("history.actorHuman");
  }
  return actor;
}

export function formatShredStateLabel(state: string): string {
  switch (state) {
    case "scheduled":
      return t("trash.stateScheduled");
    case "expedited":
      return t("trash.stateExpedited");
    case "unscheduled":
      return t("trash.stateUnscheduled");
    case "pending_confirm":
      return t("trash.statePendingConfirm");
    case "executed":
      return t("trash.stateExecuted");
    default:
      return state;
  }
}

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** Compact local timestamp (`YYYY-MM-DD HH:mm`) with zero raw UTC `Z` noise. */
export function formatLocalDateTime(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

/** Readable relative time for recent history (< 7 days), otherwise concise local date/time. */
export function formatHistoryTimestamp(ms: number, nowMs = Date.now()): string {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  const diffMs = nowMs - ms;
  if (diffMs >= 0 && diffMs < 60_000) {
    return t("history.justNow");
  }
  if (diffMs >= 60_000 && diffMs < 3_600_000) {
    return t("history.minsAgo", { count: Math.floor(diffMs / 60_000) });
  }
  if (diffMs >= 3_600_000 && diffMs < 86_400_000) {
    return t("history.hoursAgo", { count: Math.floor(diffMs / 3_600_000) });
  }
  if (diffMs >= 86_400_000 && diffMs < 7 * 86_400_000) {
    return t("history.daysAgo", { count: Math.floor(diffMs / 86_400_000) });
  }
  const d = new Date(ms);
  const locale = getLocale();
  try {
    return new Intl.DateTimeFormat(locale, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(d);
  } catch {
    return formatLocalDateTime(ms);
  }
}
