//! Signed-patch verification for Jay Squad Sec.
//!
//! The product is offline by default. The *only* thing it will ever accept from
//! outside is a patch, and it accepts one **only if that patch carries a valid
//! ed25519 signature made with the builder's private key**. That key never
//! ships; the product embeds just the matching public key. So there is no way
//! to inject code into the product without the builder's secret key, even for
//! someone who fully controls the network or the device's storage.
//!
//! Why asymmetric (ed25519) and not the engine's keyed hash: a keyed hash is
//! symmetric, so the verifier holds the same secret it checks against. Anyone
//! who extracted that secret from an installed app could forge "valid" patches.
//! With ed25519 the device holds only the public key, which cannot sign.
//!
//! The product build should depend on this crate with `default-features =
//! false` (verify-only, no signing code, no RNG) to stay lightweight. Signing
//! lives behind the `signing` feature and runs only in the offline builder
//! tool, never on a user's device.

use ed25519_compact::{PublicKey, Signature};

/// Patch wire-schema version. Bump on any breaking change to the signed layout.
pub const PATCH_SCHEMA_VERSION: u32 = 1;

/// Default cap on patch payload size (64 MiB). Bounds memory on a device and
/// blocks a decompression/allocation DoS via an enormous "patch".
pub const DEFAULT_MAX_PAYLOAD: usize = 64 * 1024 * 1024;

/// Domain-separation tag mixed into every signed message, so a Jay Squad Sec
/// signature can never be replayed as a signature for some other protocol that
/// happens to use the same key.
const DOMAIN: &[u8] = b"JSS-PATCH-v1\0";

/// Signed metadata describing a patch. Every field here is covered by the
/// signature, so none of it can be altered in transit without detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchManifest {
    pub schema_version: u32,
    pub product_id: String,
    pub patch_version: u64,
    pub payload_len: u64,
}

/// A patch as delivered: manifest, payload bytes, and the detached signature
/// over `DOMAIN || manifest || payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPatch {
    pub manifest: PatchManifest,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

/// The result of a successful verification. Holding one is proof the payload is
/// authentic, intact, for this product, and newer than what is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPatch {
    pub patch_version: u64,
    pub payload: Vec<u8>,
}

/// Why a patch was rejected. A rejected patch is never applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// Patch schema version did not match [`PATCH_SCHEMA_VERSION`].
    BadSchema { got: u32, expected: u32 },
    /// Patch was signed for a different product id.
    WrongProduct,
    /// `manifest.payload_len` disagreed with the actual payload length.
    LengthMismatch,
    /// Payload exceeded the verifier's size cap.
    PayloadTooLarge { len: usize, max: usize },
    /// Public key or signature bytes were structurally invalid.
    MalformedKeyOrSig,
    /// Signature did not verify against the embedded public key. This is the
    /// catch-all for any tampering: forged payload, altered manifest, wrong key.
    BadSignature,
    /// Signature was valid but the patch is not newer than what is installed
    /// (replay / downgrade attempt).
    Rollback { got: u64, current: u64 },
    /// A patch file could not be decoded (bad magic, wrong format version,
    /// truncated, inconsistent lengths, or non-UTF-8 product id).
    MalformedPatchFile,
    /// Patch version above [`MAX_PATCH_VERSION`]. Refused even when signed:
    /// a huge version would freeze all future updates and cannot be reported
    /// through a signed 64-bit (JNI `long`) return value.
    VersionTooLarge { got: u64 },
}

/// Highest patch version any verifier accepts (`u32::MAX`), matching the cap
/// in the builder's signing tool.
pub const MAX_PATCH_VERSION: u64 = u32::MAX as u64;

impl core::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UpdateError::BadSchema { got, expected } => {
                write!(f, "unsupported patch schema {got} (expected {expected})")
            }
            UpdateError::WrongProduct => write!(f, "patch is for a different product"),
            UpdateError::LengthMismatch => write!(f, "declared payload length does not match payload"),
            UpdateError::PayloadTooLarge { len, max } => {
                write!(f, "patch payload too large: {len} bytes (max {max})")
            }
            UpdateError::MalformedKeyOrSig => write!(f, "malformed public key or signature"),
            UpdateError::BadSignature => write!(f, "signature verification failed"),
            UpdateError::Rollback { got, current } => {
                write!(f, "patch version {got} is not newer than installed {current}")
            }
            UpdateError::MalformedPatchFile => write!(f, "patch file is malformed"),
            UpdateError::VersionTooLarge { got } => {
                write!(f, "patch version {got} exceeds the maximum {MAX_PATCH_VERSION}")
            }
        }
    }
}

impl std::error::Error for UpdateError {}

/// Magic bytes at the start of an encoded patch file.
pub const PATCH_MAGIC: &[u8; 4] = b"JSSP";
/// On-disk patch container format version (distinct from the signed schema).
pub const PATCH_FORMAT_VERSION: u16 = 1;

/// Minimal bounds-checked reader for decoding; never panics or over-reads.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], UpdateError> {
        let end = self.pos.checked_add(n).ok_or(UpdateError::MalformedPatchFile)?;
        if end > self.b.len() {
            return Err(UpdateError::MalformedPatchFile);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.pos..]
    }
}

impl SignedPatch {
    /// Serialize to the on-disk patch container (little-endian, zero-dependency):
    /// `magic | format_version | schema_version | pid_len | pid | patch_version
    /// | payload_len | signature(64) | payload`.
    pub fn encode(&self) -> Vec<u8> {
        let pid = self.manifest.product_id.as_bytes();
        let mut b = Vec::with_capacity(26 + pid.len() + 64 + self.payload.len());
        b.extend_from_slice(PATCH_MAGIC);
        b.extend_from_slice(&PATCH_FORMAT_VERSION.to_le_bytes());
        b.extend_from_slice(&self.manifest.schema_version.to_le_bytes());
        b.extend_from_slice(&(pid.len() as u32).to_le_bytes());
        b.extend_from_slice(pid);
        b.extend_from_slice(&self.manifest.patch_version.to_le_bytes());
        b.extend_from_slice(&self.manifest.payload_len.to_le_bytes());
        b.extend_from_slice(&self.signature);
        b.extend_from_slice(&self.payload);
        b
    }

    /// Decode a patch container. Fully bounds-checked: any truncation, bad
    /// magic/version, length inconsistency or non-UTF-8 product id is rejected
    /// as [`UpdateError::MalformedPatchFile`] without panicking. Decoding does
    /// NOT verify the signature; pass the result to [`Verifier::verify`].
    pub fn decode(bytes: &[u8]) -> Result<SignedPatch, UpdateError> {
        let mut c = Cursor { b: bytes, pos: 0 };
        if c.take(4)? != PATCH_MAGIC {
            return Err(UpdateError::MalformedPatchFile);
        }
        let fmt = u16::from_le_bytes(c.take(2)?.try_into().unwrap());
        if fmt != PATCH_FORMAT_VERSION {
            return Err(UpdateError::MalformedPatchFile);
        }
        let schema_version = u32::from_le_bytes(c.take(4)?.try_into().unwrap());
        let pid_len = u32::from_le_bytes(c.take(4)?.try_into().unwrap()) as usize;
        let pid_bytes = c.take(pid_len)?; // take() bounds pid_len to the buffer
        let product_id = core::str::from_utf8(pid_bytes)
            .map_err(|_| UpdateError::MalformedPatchFile)?
            .to_owned();
        let patch_version = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
        let payload_len = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
        let signature: [u8; 64] = c.take(64)?.try_into().unwrap();
        let payload = c.rest();
        if payload.len() as u64 != payload_len {
            return Err(UpdateError::MalformedPatchFile);
        }
        // Defense-in-depth: reject an oversized payload here, before allocating
        // a copy, rather than only later in Verifier::verify. payload is still
        // just a borrowed slice at this point, so this check costs no alloc.
        if payload.len() > DEFAULT_MAX_PAYLOAD {
            return Err(UpdateError::MalformedPatchFile);
        }
        Ok(SignedPatch {
            manifest: PatchManifest { schema_version, product_id, patch_version, payload_len },
            payload: payload.to_vec(),
            signature,
        })
    }
}

/// Generate a fresh ed25519 keypair as `(public_key, secret_key)` raw bytes.
/// Builder-side only (behind the `signing` feature); the secret key must be
/// kept offline and never shipped. The public key is what you embed in the app.
#[cfg(feature = "signing")]
pub fn generate_keypair() -> ([u8; 32], [u8; 64]) {
    use ed25519_compact::KeyPair;
    let kp = KeyPair::generate();
    (*kp.pk, *kp.sk)
}

/// Canonical, deterministic byte layout that gets signed and verified. Length
/// prefixes make the encoding unambiguous (no field-boundary confusion).
///
/// Public so an external signer (e.g. an HSM or offline signing service) can
/// produce a detached signature over exactly these bytes. Exposing it grants
/// nothing: a valid signature still requires the builder's private key.
pub fn signing_message(m: &PatchManifest, payload: &[u8]) -> Vec<u8> {
    let pid = m.product_id.as_bytes();
    let mut b = Vec::with_capacity(DOMAIN.len() + 28 + pid.len() + payload.len());
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(&m.schema_version.to_le_bytes());
    b.extend_from_slice(&(pid.len() as u64).to_le_bytes());
    b.extend_from_slice(pid);
    b.extend_from_slice(&m.patch_version.to_le_bytes());
    b.extend_from_slice(&m.payload_len.to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// Verifies patches against a single embedded public key and product id, and
/// refuses anything not strictly newer than the installed version.
#[derive(Clone, Debug)]
pub struct Verifier {
    /// The builder's ed25519 public key. In the shipped product this is a
    /// compiled-in constant; the matching private key exists only offline.
    pub public_key: [u8; 32],
    pub product_id: String,
    pub current_version: u64,
    pub max_payload: usize,
}

impl Verifier {
    pub fn new(public_key: [u8; 32], product_id: impl Into<String>, current_version: u64) -> Self {
        Self {
            public_key,
            product_id: product_id.into(),
            current_version,
            max_payload: DEFAULT_MAX_PAYLOAD,
        }
    }

    /// Verify a patch. Returns a [`VerifiedPatch`] only if it is authentic,
    /// intact, for this product, within the size cap, and strictly newer than
    /// the installed version. Any failure returns an error and applies nothing.
    ///
    /// Cheap structural checks run first; the anti-rollback decision runs only
    /// *after* the signature verifies, so the version it trusts is authentic.
    pub fn verify(&self, patch: &SignedPatch) -> Result<VerifiedPatch, UpdateError> {
        let m = &patch.manifest;
        if m.schema_version != PATCH_SCHEMA_VERSION {
            return Err(UpdateError::BadSchema {
                got: m.schema_version,
                expected: PATCH_SCHEMA_VERSION,
            });
        }
        if m.product_id != self.product_id {
            return Err(UpdateError::WrongProduct);
        }
        if m.patch_version > MAX_PATCH_VERSION {
            return Err(UpdateError::VersionTooLarge { got: m.patch_version });
        }
        if m.payload_len != patch.payload.len() as u64 {
            return Err(UpdateError::LengthMismatch);
        }
        if patch.payload.len() > self.max_payload {
            return Err(UpdateError::PayloadTooLarge {
                len: patch.payload.len(),
                max: self.max_payload,
            });
        }
        let pk = PublicKey::from_slice(&self.public_key).map_err(|_| UpdateError::MalformedKeyOrSig)?;
        let sig = Signature::from_slice(&patch.signature).map_err(|_| UpdateError::MalformedKeyOrSig)?;
        let msg = signing_message(m, &patch.payload);
        pk.verify(&msg, &sig).map_err(|_| UpdateError::BadSignature)?;

        // Authentic from here on: the version is now trustworthy.
        if m.patch_version <= self.current_version {
            return Err(UpdateError::Rollback {
                got: m.patch_version,
                current: self.current_version,
            });
        }
        Ok(VerifiedPatch {
            patch_version: m.patch_version,
            payload: patch.payload.clone(),
        })
    }
}

/// Builder-side signing. Behind the `signing` feature so the shipped product
/// (built with `default-features = false`) contains no signing code at all.
/// The product never calls this and never holds a secret key.
#[cfg(feature = "signing")]
pub fn sign_patch(
    secret_key: &[u8; 64],
    product_id: impl Into<String>,
    patch_version: u64,
    payload: Vec<u8>,
) -> Result<SignedPatch, UpdateError> {
    use ed25519_compact::SecretKey;
    let sk = SecretKey::from_slice(secret_key).map_err(|_| UpdateError::MalformedKeyOrSig)?;
    let manifest = PatchManifest {
        schema_version: PATCH_SCHEMA_VERSION,
        product_id: product_id.into(),
        patch_version,
        payload_len: payload.len() as u64,
    };
    let msg = signing_message(&manifest, &payload);
    let sig = sk.sign(&msg, None);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig.as_ref());
    Ok(SignedPatch { manifest, payload, signature })
}

#[cfg(test)]
mod serde_tests {
    use super::*;

    fn sample() -> SignedPatch {
        SignedPatch {
            manifest: PatchManifest {
                schema_version: PATCH_SCHEMA_VERSION,
                product_id: "jay-squad-sec-android".into(),
                patch_version: 7,
                payload_len: 5,
            },
            payload: vec![1, 2, 3, 4, 5],
            signature: [9u8; 64],
        }
    }

    #[test]
    fn encode_decode_round_trips() {
        let p = sample();
        let back = SignedPatch::decode(&p.encode()).expect("round trip");
        assert_eq!(back, p);
    }

    #[test]
    fn truncation_at_any_length_is_rejected_without_panic() {
        let bytes = sample().encode();
        for cut in 0..bytes.len() {
            assert!(SignedPatch::decode(&bytes[..cut]).is_err(), "cut at {cut} must fail");
        }
    }

    #[test]
    fn bad_magic_and_version_are_rejected() {
        let mut bad_magic = sample().encode();
        bad_magic[0] = b'X';
        assert_eq!(SignedPatch::decode(&bad_magic), Err(UpdateError::MalformedPatchFile));

        let mut bad_ver = sample().encode();
        bad_ver[4] = 0xFF; // format version byte
        assert_eq!(SignedPatch::decode(&bad_ver), Err(UpdateError::MalformedPatchFile));
    }

    #[test]
    fn payload_length_mismatch_is_rejected() {
        let mut extra = sample().encode();
        extra.push(0xFF); // one trailing byte: payload longer than payload_len
        assert_eq!(SignedPatch::decode(&extra), Err(UpdateError::MalformedPatchFile));
    }
}

#[cfg(all(test, feature = "signing"))]
mod tests {
    use super::*;
    use ed25519_compact::KeyPair;

    const PRODUCT: &str = "jay-squad-sec-android";

    struct Fixture {
        pk: [u8; 32],
        sk: [u8; 64],
    }

    fn keys() -> Fixture {
        let kp = KeyPair::generate();
        Fixture { pk: *kp.pk, sk: *kp.sk }
    }

    #[test]
    fn a_genuine_patch_verifies() {
        let k = keys();
        let patch = sign_patch(&k.sk, PRODUCT, 2, b"new-rules-blob".to_vec()).unwrap();
        let v = Verifier::new(k.pk, PRODUCT, 1);
        let out = v.verify(&patch).expect("genuine patch must verify");
        assert_eq!(out.patch_version, 2);
        assert_eq!(out.payload, b"new-rules-blob");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let k = keys();
        let mut patch = sign_patch(&k.sk, PRODUCT, 2, b"good".to_vec()).unwrap();
        patch.payload = b"evil".to_vec();
        patch.manifest.payload_len = patch.payload.len() as u64; // keep lengths consistent
        let v = Verifier::new(k.pk, PRODUCT, 1);
        assert_eq!(v.verify(&patch), Err(UpdateError::BadSignature));
    }

    #[test]
    fn altered_version_is_rejected() {
        let k = keys();
        let mut patch = sign_patch(&k.sk, PRODUCT, 2, b"blob".to_vec()).unwrap();
        patch.manifest.patch_version = 999; // not re-signed
        let v = Verifier::new(k.pk, PRODUCT, 1);
        assert_eq!(v.verify(&patch), Err(UpdateError::BadSignature));
    }

    #[test]
    fn a_different_key_cannot_forge() {
        let signer = keys();
        let attacker_device_key = keys().pk; // product embeds a DIFFERENT key
        let patch = sign_patch(&signer.sk, PRODUCT, 2, b"blob".to_vec()).unwrap();
        let v = Verifier::new(attacker_device_key, PRODUCT, 1);
        assert_eq!(v.verify(&patch), Err(UpdateError::BadSignature));
    }

    #[test]
    fn downgrade_and_replay_are_rejected() {
        let k = keys();
        // Signed version equals installed -> rollback.
        let same = sign_patch(&k.sk, PRODUCT, 5, b"x".to_vec()).unwrap();
        let v = Verifier::new(k.pk, PRODUCT, 5);
        assert_eq!(v.verify(&same), Err(UpdateError::Rollback { got: 5, current: 5 }));
        // Older than installed -> rollback.
        let older = sign_patch(&k.sk, PRODUCT, 3, b"x".to_vec()).unwrap();
        let v2 = Verifier::new(k.pk, PRODUCT, 10);
        assert_eq!(v2.verify(&older), Err(UpdateError::Rollback { got: 3, current: 10 }));
    }

    #[test]
    fn wrong_product_is_rejected() {
        let k = keys();
        let patch = sign_patch(&k.sk, "some-other-app", 2, b"x".to_vec()).unwrap();
        let v = Verifier::new(k.pk, PRODUCT, 1);
        assert_eq!(v.verify(&patch), Err(UpdateError::WrongProduct));
    }

    #[test]
    fn length_mismatch_is_rejected_before_crypto() {
        let k = keys();
        let mut patch = sign_patch(&k.sk, PRODUCT, 2, b"1234".to_vec()).unwrap();
        patch.manifest.payload_len = 9999;
        let v = Verifier::new(k.pk, PRODUCT, 1);
        assert_eq!(v.verify(&patch), Err(UpdateError::LengthMismatch));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let k = keys();
        let patch = sign_patch(&k.sk, PRODUCT, 2, vec![0u8; 1024]).unwrap();
        let mut v = Verifier::new(k.pk, PRODUCT, 1);
        v.max_payload = 512;
        assert_eq!(
            v.verify(&patch),
            Err(UpdateError::PayloadTooLarge { len: 1024, max: 512 })
        );
    }

    #[test]
    fn bad_schema_is_rejected() {
        let k = keys();
        let mut patch = sign_patch(&k.sk, PRODUCT, 2, b"x".to_vec()).unwrap();
        patch.manifest.schema_version = 99;
        let v = Verifier::new(k.pk, PRODUCT, 1);
        assert_eq!(
            v.verify(&patch),
            Err(UpdateError::BadSchema { got: 99, expected: PATCH_SCHEMA_VERSION })
        );
    }

    #[test]
    fn verify_never_panics_on_garbage() {
        let v = Verifier::new([0u8; 32], PRODUCT, 1);
        let patch = SignedPatch {
            manifest: PatchManifest {
                schema_version: PATCH_SCHEMA_VERSION,
                product_id: PRODUCT.into(),
                patch_version: 2,
                payload_len: 3,
            },
            payload: vec![1, 2, 3],
            signature: [0xAB; 64],
        };
        let _ = v.verify(&patch); // all-zero key, junk sig: must not panic
    }

    #[test]
    fn versions_above_u32_max_are_refused_even_when_signed() {
        let (pk, sk) = generate_keypair();
        let v = Verifier::new(pk, "p", 0);
        assert!(v.verify(&sign_patch(&sk, "p", MAX_PATCH_VERSION, vec![1]).unwrap()).is_ok());
        let big = sign_patch(&sk, "p", MAX_PATCH_VERSION + 1, vec![1]).unwrap();
        assert_eq!(v.verify(&big), Err(UpdateError::VersionTooLarge { got: MAX_PATCH_VERSION + 1 }));
    }
}
