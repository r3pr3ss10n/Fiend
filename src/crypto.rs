use anyhow::{Result, anyhow};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::AeadInPlace};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn parse_key(hex_str: &str) -> Result<Vec<u8>> {
    if hex_str.len() != 64 {
        return Err(anyhow!("key must be 64 hex characters (32 bytes)"));
    }
    hex::decode(hex_str).map_err(|e| anyhow!("invalid hex: {}", e))
}

pub fn derive_keys(master_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut transport_secret = vec![0u8; 32];
    hk.expand(b"stw-transport", &mut transport_secret)
        .map_err(|_| anyhow!("derive transport secret failed"))?;

    let mut auth_psk = vec![0u8; 32];
    hk.expand(b"stw-auth-psk", &mut auth_psk)
        .map_err(|_| anyhow!("derive auth PSK failed"))?;

    Ok((transport_secret, auth_psk))
}

pub fn auth_proof(psk: &[u8], label: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC can take key of any size");
    mac.update(label.as_bytes());

    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

pub fn verify_auth_proof(psk: &[u8], label: &str, proof: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC can take key of any size");
    mac.update(label.as_bytes());

    let Ok(proof_bytes) = hex::decode(proof) else {
        return false;
    };
    mac.verify_slice(&proof_bytes).is_ok()
}

pub struct RecordCipher {
    cipher: ChaCha20Poly1305,
    iv: [u8; 12],
    counter: u64,
}

impl RecordCipher {
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let counter_bytes = self.counter.to_le_bytes();
        for i in 0..8 {
            nonce[i] ^= counter_bytes[i];
        }
        nonce
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) -> [u8; 16] {
        let nonce_bytes = self.nonce();
        self.counter += 1;
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), b"", buf)
            .expect("encryption failed");
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag);
        out
    }

    pub fn decrypt(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        if buf.len() < 16 {
            return Err(anyhow!("decryption failed"));
        }
        let nonce_bytes = self.nonce();
        self.counter += 1;
        let tag_pos = buf.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[tag_pos..]);
        buf.truncate(tag_pos);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                b"",
                buf.as_mut_slice(),
                GenericArray::from_slice(&tag),
            )
            .map_err(|_| anyhow!("decryption failed"))
    }
}

pub fn derive_session_keys(
    secret: &[u8],
    tls_random: &[u8],
    is_client: bool,
) -> Result<(RecordCipher, RecordCipher)> {
    let hk = Hkdf::<Sha256>::new(Some(tls_random), secret);

    let mut c2s_key = [0u8; 32];
    hk.expand(b"c2s-key", &mut c2s_key)
        .map_err(|_| anyhow!("derive c2s-key failed"))?;

    let mut s2c_key = [0u8; 32];
    hk.expand(b"s2c-key", &mut s2c_key)
        .map_err(|_| anyhow!("derive s2c-key failed"))?;

    let mut c2s_iv = [0u8; 12];
    hk.expand(b"c2s-iv", &mut c2s_iv)
        .map_err(|_| anyhow!("derive c2s-iv failed"))?;

    let mut s2c_iv = [0u8; 12];
    hk.expand(b"s2c-iv", &mut s2c_iv)
        .map_err(|_| anyhow!("derive s2c-iv failed"))?;

    let c2s = RecordCipher {
        cipher: <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(Key::from_slice(&c2s_key)),
        iv: c2s_iv,
        counter: 0,
    };

    let s2c = RecordCipher {
        cipher: <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(Key::from_slice(&s2c_key)),
        iv: s2c_iv,
        counter: 0,
    };

    if is_client {
        Ok((c2s, s2c))
    } else {
        Ok((s2c, c2s))
    }
}
