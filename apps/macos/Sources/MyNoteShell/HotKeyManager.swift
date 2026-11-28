import Carbon
import Foundation

struct HotKeyPreset: Equatable, Sendable {
    let id: String
    let label: String
    let keyCode: UInt32
    let modifiers: UInt32

    static let all: [HotKeyPreset] = [
        HotKeyPreset(
            id: "ctrl_opt_space",
            label: "⌃⌥Space",
            keyCode: UInt32(kVK_Space),
            modifiers: UInt32(controlKey | optionKey)
        ),
        HotKeyPreset(
            id: "opt_space",
            label: "⌥Space",
            keyCode: UInt32(kVK_Space),
            modifiers: UInt32(optionKey)
        ),
        HotKeyPreset(
            id: "opt_cmd_n",
            label: "⌥⌘N",
            keyCode: UInt32(kVK_ANSI_N),
            modifiers: UInt32(optionKey | cmdKey)
        ),
        HotKeyPreset(
            id: "ctrl_opt_n",
            label: "⌃⌥N",
            keyCode: UInt32(kVK_ANSI_N),
            modifiers: UInt32(controlKey | optionKey)
        ),
    ]

    static let defaultPreset = all[0]

    static func byID(_ id: String?) -> HotKeyPreset {
        guard let id else { return defaultPreset }
        return all.first(where: { $0.id == id }) ?? defaultPreset
    }
}

private func fourCharCode(_ string: String) -> OSType {
    var result: OSType = 0
    for byte in string.utf8.prefix(4) {
        result = (result << 8) | OSType(byte)
    }
    return result
}

private let kMyNoteHotKeySignature: OSType = fourCharCode("MNOT")
private let kMyNoteHotKeyID: UInt32 = 1

/// Global hotkey via Carbon `RegisterEventHotKey` (requires ZERO Accessibility permissions).
@MainActor
final class HotKeyManager {
    private var eventHandler: EventHandlerRef?
    private var hotKeyRef: EventHotKeyRef?
    private let onTrigger: () -> Void
    private(set) var currentPreset: HotKeyPreset = .defaultPreset

    private static weak var sharedInstance: HotKeyManager?

    init(onTrigger: @escaping () -> Void) {
        self.onTrigger = onTrigger
        HotKeyManager.sharedInstance = self
        installHandlerIfNeeded()
    }

    deinit {
        if let ref = hotKeyRef {
            UnregisterEventHotKey(ref)
        }
        if let handler = eventHandler {
            RemoveEventHandler(handler)
        }
    }

    @discardableResult
    func register(preset: HotKeyPreset) -> OSStatus {
        unregister()
        var ref: EventHotKeyRef?
        let hotKeyID = EventHotKeyID(signature: kMyNoteHotKeySignature, id: kMyNoteHotKeyID)
        let status = RegisterEventHotKey(
            preset.keyCode,
            preset.modifiers,
            hotKeyID,
            GetApplicationEventTarget(),
            0,
            &ref
        )
        if status == noErr, let ref {
            hotKeyRef = ref
            currentPreset = preset
        }
        return status
    }

    func unregister() {
        if let ref = hotKeyRef {
            UnregisterEventHotKey(ref)
            hotKeyRef = nil
        }
    }

    private func installHandlerIfNeeded() {
        guard eventHandler == nil else { return }
        var eventSpec = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard),
            eventKind: UInt32(kEventHotKeyPressed)
        )
        let callback: EventHandlerUPP = { _, event, _ in
            var hotKeyID = EventHotKeyID()
            let err = GetEventParameter(
                event,
                EventParamName(kEventParamDirectObject),
                EventParamType(typeEventHotKeyID),
                nil,
                MemoryLayout<EventHotKeyID>.size,
                nil,
                &hotKeyID
            )
            if err == noErr,
               hotKeyID.signature == kMyNoteHotKeySignature,
               hotKeyID.id == kMyNoteHotKeyID
            {
                DispatchQueue.main.async {
                    HotKeyManager.sharedInstance?.onTrigger()
                }
            }
            return noErr
        }
        InstallEventHandler(
            GetApplicationEventTarget(),
            callback,
            1,
            &eventSpec,
            nil,
            &eventHandler
        )
    }
}
