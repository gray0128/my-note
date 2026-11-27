// ---------- S-Clip-2 Prototype: Independent Clipboard MNC1 Codec (`WasmClipCodec`) ----------
// SSOT contract: `docs/interface-contracts.md` §5, `docs/data-structures.md` §3.3 & §3.8.

#[cfg(feature = "pwa")]
#[wasm_bindgen]
pub struct WasmClipCodec {
    device_id: DeviceId,
    clip_kid: mynote_core::ids::Ulid,
    clip_key: Option<Zeroizing<[u8; 32]>>,
}

#[cfg(feature = "pwa")]
impl WasmClipCodec {
    fn require_key(&self) -> Result<&[u8; 32], CoreError> {
        self.clip_key.as_deref().ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                "ClipKey has been zeroized",
                "Re-initialize WasmClipCodec with the active ClipKey",
            )
        })
    }

    pub fn new_inner(
        device_id: &str,
        clip_kid: &str,
        clip_key_bytes: &[u8],
    ) -> Result<Self, CoreError> {
        let dev = DeviceId::parse(device_id)?;
        let kid = mynote_core::ids::Ulid::parse(clip_kid)?;
        if clip_key_bytes.len() != 32 {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("clipKeyBytes must be 32 bytes, got {}", clip_key_bytes.len()),
                "Provide a 32-byte ClipKey",
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(clip_key_bytes);
        Ok(Self {
            device_id: dev,
            clip_kid: kid,
            clip_key: Some(key),
        })
    }

    pub fn encrypt_meta_inner(
        &self,
        clip_id: &str,
        meta_json: &str,
        ephemeral: bool,
    ) -> Result<Vec<u8>, CoreError> {
        let key = self.require_key()?;
        let cid = mynote_core::ids::Ulid::parse(clip_id)?;
        let nonce = fill_random::<24>()?;
        mynote_core::clip::encrypt_mnc1_meta(
            self.clip_kid,
            key,
            cid,
            &self.device_id,
            meta_json,
            ephemeral,
            nonce,
        )
    }

    pub fn decrypt_meta_inner(
        &self,
        clip_id: &str,
        author_device_id: &str,
        envelope: &[u8],
        ephemeral: bool,
    ) -> Result<String, CoreError> {
        let key = self.require_key()?;
        let cid = mynote_core::ids::Ulid::parse(clip_id)?;
        let author = DeviceId::parse(author_device_id)?;
        mynote_core::clip::decrypt_mnc1_meta(self.clip_kid, key, cid, &author, ephemeral, envelope)
    }

    pub fn encrypt_blob_inner(&self, clip_id: &str, raw_bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
        let key = self.require_key()?;
        let cid = mynote_core::ids::Ulid::parse(clip_id)?;
        let nonce = fill_random::<24>()?;
        mynote_core::clip::encrypt_mnc1_blob(
            self.clip_kid,
            key,
            cid,
            &self.device_id,
            raw_bytes,
            nonce,
        )
    }

    pub fn decrypt_blob_inner(
        &self,
        clip_id: &str,
        author_device_id: &str,
        envelope: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let key = self.require_key()?;
        let cid = mynote_core::ids::Ulid::parse(clip_id)?;
        let author = DeviceId::parse(author_device_id)?;
        mynote_core::clip::decrypt_mnc1_blob(self.clip_kid, key, cid, &author, envelope)
    }
}

#[cfg(feature = "pwa")]
#[wasm_bindgen]
impl WasmClipCodec {
    #[wasm_bindgen(constructor)]
    pub fn new(
        device_id: &str,
        clip_kid: &str,
        clip_key_bytes: &[u8],
    ) -> Result<WasmClipCodec, JsValue> {
        Self::new_inner(device_id, clip_kid, clip_key_bytes).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = encryptMeta)]
    pub fn encrypt_meta(
        &self,
        clip_id: &str,
        meta_json: &str,
        ephemeral: bool,
    ) -> Result<Vec<u8>, JsValue> {
        self.encrypt_meta_inner(clip_id, meta_json, ephemeral)
            .map_err(err_to_js)
    }

    /// `ephemeral` is optional for signature compatibility with `docs/interface-contracts.md` §5
    /// (defaults to `false`, and when passed explicitly enforces exact `flags` bit 0 in AAD).
    #[wasm_bindgen(js_name = decryptMeta)]
    pub fn decrypt_meta(
        &self,
        clip_id: &str,
        author_device_id: &str,
        envelope: &[u8],
        ephemeral: Option<bool>,
    ) -> Result<String, JsValue> {
        self.decrypt_meta_inner(clip_id, author_device_id, envelope, ephemeral.unwrap_or(false))
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = encryptBlob)]
    pub fn encrypt_blob(&self, clip_id: &str, raw_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.encrypt_blob_inner(clip_id, raw_bytes)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = decryptBlob)]
    pub fn decrypt_blob(
        &self,
        clip_id: &str,
        author_device_id: &str,
        envelope: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        self.decrypt_blob_inner(clip_id, author_device_id, envelope)
            .map_err(err_to_js)
    }

    #[wasm_bindgen]
    pub fn zeroize(&mut self) {
        if let Some(mut k) = self.clip_key.take() {
            k.zeroize();
        }
    }
}

#[cfg(feature = "pwa")]
impl Drop for WasmClipCodec {
    fn drop(&mut self) {
        self.zeroize();
    }
}
