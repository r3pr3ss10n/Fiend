mod parse;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::transport::disguise::tls::{derive_psk_identity, derive_ticket_age};
pub use parse::parse_client_hello;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldOffset {
    pub offset: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreaseField {
    pub value_offset: usize,
    pub data_offset: Option<usize>,
    pub data_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintTemplate {
    pub domain: String,
    pub raw: String,
    pub tls_random: FieldOffset,
    pub session_id: FieldOffset,
    pub key_share: FieldOffset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_identity: Option<FieldOffset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_age: Option<FieldOffset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_binder: Option<FieldOffset>,
    #[serde(default)]
    pub grease: Vec<GreaseField>,
}

impl FingerprintTemplate {
    pub fn load(path: &str) -> Result<Self> {
        let full_path = if path.ends_with(".json") {
            path.to_string()
        } else {
            format!("{}.json", path)
        };
        let content = std::fs::read_to_string(&full_path)
            .with_context(|| format!("read fingerprint: {}", full_path))?;
        let template: Self = serde_json::from_str(&content).context("parse fingerprint JSON")?;
        template.validate()?;
        Ok(template)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn raw_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.raw).context("decode template hex")
    }

    pub fn build(&self, secret: &[u8]) -> Result<Vec<u8>> {
        let mut record = self.raw_bytes()?;

        let mut tls_random = [0u8; 32];
        rand::rng().fill(&mut tls_random[..]);
        patch(&mut record, &self.tls_random, &tls_random);

        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
        mac.update(&tls_random);
        let sid = mac.finalize().into_bytes();
        patch(&mut record, &self.session_id, &sid);

        let mut key_share = vec![0u8; self.key_share.size];
        rand::rng().fill(&mut key_share[..]);
        patch(&mut record, &self.key_share, &key_share);

        if let Some(ref psk_identity) = self.psk_identity {
            let derived = derive_psk_identity(secret);
            let mut psk_id = vec![0u8; psk_identity.size];
            let n = derived.len().min(psk_identity.size);
            psk_id[..n].copy_from_slice(&derived[..n]);
            if psk_identity.size > derived.len() {
                rand::rng().fill(&mut psk_id[n..]);
            }
            patch(&mut record, psk_identity, &psk_id);
        }

        if let Some(ref ticket_age) = self.ticket_age {
            let ta = derive_ticket_age(secret);
            patch(&mut record, ticket_age, &ta);
        }

        if let Some(ref psk_binder) = self.psk_binder {
            let mut binder = vec![0u8; psk_binder.size];
            rand::rng().fill(&mut binder[..]);
            patch(&mut record, psk_binder, &binder);
        }

        for g in &self.grease {
            let val = random_grease();
            record[g.value_offset] = val;
            record[g.value_offset + 1] = val;
            if let (Some(offset), Some(size)) = (g.data_offset, g.data_size) {
                rand::rng().fill(&mut record[offset..offset + size]);
            }
        }

        Ok(record)
    }

    pub fn verify(&self, original: &[u8]) -> Result<()> {
        let built = self.build(&[0u8; 16])?;

        if built.len() != original.len() {
            anyhow::bail!(
                "length mismatch: original {} vs built {}",
                original.len(),
                built.len()
            );
        }

        let mut dynamic_mask = vec![false; original.len()];
        let mark = |mask: &mut Vec<bool>, offset: usize, size: usize| {
            for i in offset..offset + size {
                if i < mask.len() {
                    mask[i] = true;
                }
            }
        };

        mark(
            &mut dynamic_mask,
            self.tls_random.offset,
            self.tls_random.size,
        );
        mark(
            &mut dynamic_mask,
            self.session_id.offset,
            self.session_id.size,
        );
        mark(
            &mut dynamic_mask,
            self.key_share.offset,
            self.key_share.size,
        );
        if let Some(ref f) = self.psk_identity {
            mark(&mut dynamic_mask, f.offset, f.size);
        }
        if let Some(ref f) = self.ticket_age {
            mark(&mut dynamic_mask, f.offset, f.size);
        }
        if let Some(ref f) = self.psk_binder {
            mark(&mut dynamic_mask, f.offset, f.size);
        }

        for g in &self.grease {
            mark(&mut dynamic_mask, g.value_offset, 2);
            if let (Some(offset), Some(size)) = (g.data_offset, g.data_size) {
                mark(&mut dynamic_mask, offset, size);
            }
        }

        let mut mismatches = Vec::new();
        for i in 0..original.len() {
            if !dynamic_mask[i] && original[i] != built[i] {
                mismatches.push(i);
            }
        }

        if !mismatches.is_empty() {
            let details: Vec<String> = mismatches
                .iter()
                .take(10)
                .map(|&i| {
                    format!(
                        "  byte {}: original 0x{:02x} vs built 0x{:02x}",
                        i, original[i], built[i]
                    )
                })
                .collect();
            anyhow::bail!(
                "{} unexpected byte difference(s) outside dynamic fields:\n{}",
                mismatches.len(),
                details.join("\n")
            );
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        let raw = self.raw_bytes()?;
        for (name, f) in [
            ("tls_random", &self.tls_random),
            ("session_id", &self.session_id),
            ("key_share", &self.key_share),
        ] {
            if f.offset + f.size > raw.len() {
                anyhow::bail!(
                    "{} offset {}+{} exceeds record length {}",
                    name,
                    f.offset,
                    f.size,
                    raw.len()
                );
            }
        }
        for (name, f) in [
            ("psk_identity", &self.psk_identity),
            ("ticket_age", &self.ticket_age),
            ("psk_binder", &self.psk_binder),
        ] {
            if let Some(f) = f
                && f.offset + f.size > raw.len()
            {
                anyhow::bail!(
                    "{} offset {}+{} exceeds record length {}",
                    name,
                    f.offset,
                    f.size,
                    raw.len()
                );
            }
        }
        for (i, g) in self.grease.iter().enumerate() {
            if g.value_offset + 2 > raw.len() {
                anyhow::bail!(
                    "grease[{}] value_offset {} exceeds record length",
                    i,
                    g.value_offset
                );
            }
            if let (Some(offset), Some(size)) = (g.data_offset, g.data_size)
                && offset + size > raw.len()
            {
                anyhow::bail!(
                    "grease[{}] data {}+{} exceeds record length",
                    i,
                    offset,
                    size
                );
            }
        }
        Ok(())
    }
}

fn patch(record: &mut [u8], field: &FieldOffset, data: &[u8]) {
    record[field.offset..field.offset + field.size].copy_from_slice(data);
}

fn random_grease() -> u8 {
    let nibble: u8 = rand::random::<u8>() & 0xF0;
    nibble | 0x0A
}
