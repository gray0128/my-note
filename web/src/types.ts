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

export interface BlockHistoryEntryDto {
  op_id: string;
  op_type: string;
  hlc: string;
  device_id: string;
  actor: string;
  content_available: boolean;
  has_content: boolean;
  is_locked: boolean;
  shredded: boolean;
  key_id: string | null;
  created_at_ms: number;
}

export interface BlockHistoryContentDto {
  block_id: string;
  op_id: string;
  op_type: string;
  hlc: string;
  device_id: string;
  actor: string;
  created_at_ms: number;
  is_locked: boolean;
  key_id: string;
  lang: string | null;
  content: string | null;
  mnb1_b64: string | null;
  mnw1_b64: string | null;
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

export interface VaultHeaderDto {
  gen: number;
  blob_b64: string;
  updated_at_ms: number;
}

export interface BlockedTier2OpDto {
  op_id: string;
  block_id: string;
  buffer_id: string;
  lang: string;
  public_hint: string | null;
  old_key_id: string;
  reason: string;
  mnb1_b64: string;
  mnw1_b64: string | null;
  head_op_ids: string[];
}

export interface TrashActionPrepareResponse {
  confirm_nonce: string;
  expires_in_ms: number;
  summary: {
    action: "expedite" | "confirm_pending" | "purge_history";
    block_count: number;
    key_count: number;
    grace_ms: number;
    earliest_not_before_ms: number | null;
  };
}

export interface BootstrapResponse {
  buffers: BufferDto[];
  initial_buffer_id: string | null;
  blocks: BlockDto[];
  sync_status: SyncStatusDto;
  vault_header: VaultHeaderDto | null;
  recovery_pk_b64?: string | null;
  blocked_tier2_ops?: BlockedTier2OpDto[];
  trash_count: number;
  clip_count?: number;
  daemon_version?: string;
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

export type ClipKind = "text" | "image";
export type ClipScope = "local" | "cloud" | "all";
export type ClipSourceMode = "explicit" | "auto";
export type ClipAutoApplyMirrorMode = "inbox-only" | "auto-apply";
export type AllowedClipImageMime = "image/png" | "image/jpeg" | "image/webp" | "image/gif";

export interface CloudClipQuotaDto {
  used_bytes: number;
  limit_bytes: number;
  item_count: number;
  item_limit: number;
}

export interface ClipItemDto {
  clip_id: string;
  clip_kid: string;
  device_id: string;
  kind: ClipKind;
  mime: string;
  source_mode: ClipSourceMode;
  created_at_ms: number;
  expires_at_ms: number;
  text_preview: string | null;
  has_blob: boolean;
  blob_bytes: number | null;
  blob_sha256: string | null;
  width: number | null;
  height: number | null;
  thumb_mime: string | null;
  thumb_data_url: string | null;
  cached_locally: boolean;
}

export interface ClipListResponse {
  items: ClipItemDto[];
  has_more?: boolean;
  total_count?: number;
  local_blob_bytes?: number;
  local_blob_files?: number;
  uncached_blob_items?: number;
  cloud_quota?: CloudClipQuotaDto | null;
  has_undo: boolean;
  watch_enabled: boolean;
  watch_paused: boolean;
  auto_apply_mirror: ClipAutoApplyMirrorMode;
}

export interface ClipPruneInput {
  scope: ClipScope;
  before_days?: number;
  before_ms?: number;
  keep_latest?: number;
  kind?: ClipKind;
  dry_run?: boolean;
}

export interface ClipPruneResponse {
  dry_run: boolean;
  scope: ClipScope;
  matched_count: number;
  deleted_count: number;
  freed_bytes: number;
  cloud_quota?: CloudClipQuotaDto | null;
}

export interface ClipPushTextInput {
  kind: "text";
  text: string;
  ephemeral?: boolean;
}

export interface ClipPushImageInput {
  kind: "image";
  mime: AllowedClipImageMime;
  data_b64: string;
  width?: number;
  height?: number;
  thumb_mime?: AllowedClipImageMime;
  thumb_b64?: string;
}

export interface ClipPushResponse {
  clip_id: string;
  ephemeral: boolean;
  delivered_to?: number;
  item: ClipItemDto | null;
}

export interface ClipDeleteResponse {
  deleted_count: number;
  scope?: ClipScope;
  local_deleted?: number;
  cloud_deleted?: number;
  freed_bytes?: number;
  cloud_quota?: CloudClipQuotaDto | null;
}

export interface ClipApplyResponse {
  applied: boolean;
  clip_id: string;
  has_undo: boolean;
}

export interface ClipPromoteResponse {
  block: BlockDto;
}

export interface ClipUndoResponse {
  restored: boolean;
}

export interface ClipWatchResponse {
  watch_enabled: boolean;
  watch_paused: boolean;
  auto_apply_mirror: ClipAutoApplyMirrorMode;
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
    | "DEVICE_REVOKED"
    | "CLIP_SECRET_BLOCKED"
    | "DAEMON_UPDATED";
  details: Record<string, unknown>;
}

export type LocalWsFrame =
  | { type: "blocks_changed"; upserted: BlockDto[]; deleted_ids: string[] }
  | { type: "buffers_changed"; upserted: BufferDto[]; deleted_ids: string[] }
  | { type: "trash_changed"; count: number; pending_confirm_count: number; next_shred_ms: number | null }
  | { type: "sync_status"; state: SyncStateLabel; last_seq: number; pending_ops?: number }
  | { type: "vault_header_changed"; vault_header: VaultHeaderDto }
  | {
      type: "clip_changed";
      upserted: ClipItemDto[];
      deleted_ids: string[];
      cleared: boolean;
      watch_enabled?: boolean;
      watch_paused: boolean;
      auto_apply_mirror?: ClipAutoApplyMirrorMode;
      cloud_quota?: CloudClipQuotaDto | null;
    }
  | AlertFrame;

