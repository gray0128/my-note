/** DTOs mirroring `docs/interface-contracts.md` §3.2 & §3.3. */

export type SyncStateLabel = "synced" | "syncing" | "pending_offline" | "unconfigured" | "conflict_present";

export interface BufferDto {
  id: string;
  name: string;
  position: string;
  updated_at_ms: number;
}

export interface BlockVersionDto {
  op_id: string;
  hlc: string;
  device_id: string;
  actor: string;
  is_display: boolean;
  is_locked: boolean;
  key_id: string | null;
  content: string | null;
  mnb1_b64?: string | null;
  mnw1_b64?: string | null;
}

export interface BlockDto {
  id: string;
  buffer_id: string;
  buffer_name?: string;
  position: string;
  lang: string;
  is_locked: boolean;
  has_unlocked_concurrent_version: boolean;
  public_hint: string | null;
  head_op_ids: string[];
  display_op_id: string | null;
  has_conflict: boolean;
  content: string | null;
  versions: BlockVersionDto[];
  updated_at_ms: number;
}

export interface TrashItemDto {
  id: string;
  buffer_id: string;
  buffer_name: string;
  is_locked: boolean;
  preview: string | null;
  deleted_at_ms: number;
  deleted_by_device: string;
  actor: string;
  shred_not_before_ms: number | null;
  shred_state: string;
}

export interface SyncStatusDto {
  sync_state: SyncStateLabel;
  epoch: string | null;
  last_seq: number;
  pending_ops: number;
  blocked_ops: number;
  clock_skew_ms: number;
  key_self_check: {
    ok: boolean;
    last_run_ms: number;
    blocks_missing_key: number;
  };
  trash: {
    count: number;
    pending_confirm_count: number;
    next_shred_ms: number | null;
  };
  recovery_drill_due: boolean;
  last_recovery_drill_ms: number | null;
  last_local_backup_ms: number | null;
}

export interface BootstrapResponse {
  buffers: BufferDto[];
  initial_buffer_id: string | null;
  blocks: BlockDto[];
  sync_status: SyncStatusDto;
  vault_header: unknown | null;
  trash_count: number;
  device_id: string;
  last_hlc: string | null;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  hint?: string;
  retryable?: boolean;
  details?: Record<string, unknown>;
}

export interface AlertFrame {
  type: "alert";
  code:
    | "KEY_MISSING"
    | "SHRED_PENDING_CONFIRM"
    | "NEEDS_VAULT_REKEY"
    | "CLOCK_SKEW"
    | "RECOVERY_DRILL_DUE"
    | "AUTH_REQUIRED"
    | "DEVICE_REVOKED";
  details: Record<string, unknown>;
}

export type LocalWsFrame =
  | { type: "blocks_changed"; upserted: BlockDto[]; deleted_ids: string[] }
  | { type: "buffers_changed"; upserted: BufferDto[]; deleted_ids: string[] }
  | { type: "trash_changed"; count: number; pending_confirm_count: number; next_shred_ms: number | null }
  | { type: "sync_status"; state: SyncStateLabel; last_seq: number; pending_ops?: number }
  | AlertFrame;
