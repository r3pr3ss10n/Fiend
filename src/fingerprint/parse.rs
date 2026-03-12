use anyhow::{Result, ensure};

use super::{FieldOffset, FingerprintTemplate, GreaseField};

pub fn parse_client_hello(raw: &[u8]) -> Result<FingerprintTemplate> {
    ensure!(raw.len() >= 44, "record too short");
    ensure!(
        raw[0] == 0x16,
        "not a TLS handshake record (0x{:02x})",
        raw[0]
    );

    let record_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    ensure!(raw.len() >= 5 + record_len, "record truncated");
    ensure!(
        raw[5] == 0x01,
        "not a ClientHello (handshake type 0x{:02x})",
        raw[5]
    );

    let tls_random = FieldOffset {
        offset: 11,
        size: 32,
    };

    let sid_len = raw[43] as usize;
    ensure!(
        sid_len == 32,
        "session_id must be 32 bytes, got {}",
        sid_len
    );
    let session_id = FieldOffset {
        offset: 44,
        size: 32,
    };

    let mut grease = Vec::new();

    let mut pos = 44 + sid_len;
    let cs_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    pos += 2;
    scan_grease_u16_list(raw, pos, cs_len, &mut grease);
    pos += cs_len;

    let comp_len = raw[pos] as usize;
    pos += 1 + comp_len;

    ensure!(raw.len() > pos + 2, "truncated at extensions length");
    let ext_total_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
    let ext_start = pos + 2;
    let ext_end = ext_start + ext_total_len;
    ensure!(raw.len() >= ext_end, "extensions truncated");

    let mut domain = None;
    let mut key_share = None;
    let mut psk_identity = None;
    let mut ticket_age = None;
    let mut psk_binder = None;

    let mut p = ext_start;
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([raw[p], raw[p + 1]]);
        let ext_len = u16::from_be_bytes([raw[p + 2], raw[p + 3]]) as usize;
        let ext_data = p + 4;
        ensure!(
            ext_data + ext_len <= ext_end,
            "extension 0x{:04x} truncated",
            ext_type
        );

        if is_grease(ext_type) {
            grease.push(GreaseField {
                value_offset: p,
                data_offset: if ext_len > 0 { Some(ext_data) } else { None },
                data_size: if ext_len > 0 { Some(ext_len) } else { None },
            });
        } else {
            match ext_type {
                0x0000 => domain = Some(parse_sni(&raw[ext_data..ext_data + ext_len])?),
                0x000A => scan_grease_u16_list(raw, ext_data + 2, ext_len - 2, &mut grease),
                0x000D => scan_grease_u16_list(raw, ext_data + 2, ext_len - 2, &mut grease),
                0x002B => {
                    if ext_len >= 2 {
                        let versions_len = raw[ext_data] as usize;
                        scan_grease_u16_list(raw, ext_data + 1, versions_len, &mut grease);
                    }
                }
                0x0033 => {
                    let (ks, ks_grease) = parse_key_share(raw, ext_data, ext_len)?;
                    key_share = Some(ks);
                    grease.extend(ks_grease);
                }
                0x0029 => {
                    let (pi, ta, pb) = parse_psk(raw, ext_data, ext_len)?;
                    psk_identity = Some(pi);
                    ticket_age = Some(ta);
                    psk_binder = Some(pb);
                }
                _ => {}
            }
        }

        p = ext_data + ext_len;
    }

    Ok(FingerprintTemplate {
        domain: domain.ok_or_else(|| anyhow::anyhow!("no SNI extension found"))?,
        raw: hex::encode(raw),
        tls_random,
        session_id,
        key_share: key_share.ok_or_else(|| anyhow::anyhow!("no key_share extension found"))?,
        psk_identity,
        ticket_age,
        psk_binder,
        grease,
    })
}

fn is_grease(val: u16) -> bool {
    val & 0x0F0F == 0x0A0A && (val >> 8) == (val & 0xFF)
}

fn scan_grease_u16_list(raw: &[u8], start: usize, len: usize, out: &mut Vec<GreaseField>) {
    let mut i = 0;
    while i + 1 < len {
        let val = u16::from_be_bytes([raw[start + i], raw[start + i + 1]]);
        if is_grease(val) {
            out.push(GreaseField {
                value_offset: start + i,
                data_offset: None,
                data_size: None,
            });
        }
        i += 2;
    }
}

fn parse_sni(data: &[u8]) -> Result<String> {
    ensure!(data.len() >= 5, "SNI too short");
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    ensure!(data.len() >= 5 + name_len, "SNI name truncated");
    String::from_utf8(data[5..5 + name_len].to_vec())
        .map_err(|_| anyhow::anyhow!("SNI domain not valid UTF-8"))
}

fn parse_key_share(
    raw: &[u8],
    ext_data: usize,
    ext_len: usize,
) -> Result<(FieldOffset, Vec<GreaseField>)> {
    ensure!(ext_len >= 2, "key_share too short");
    let mut grease = Vec::new();
    let mut result = None;
    let mut p = ext_data + 2;
    let end = ext_data + ext_len;

    while p + 4 <= end {
        let group = u16::from_be_bytes([raw[p], raw[p + 1]]);
        let kex_len = u16::from_be_bytes([raw[p + 2], raw[p + 3]]) as usize;
        let kex_start = p + 4;

        if is_grease(group) {
            grease.push(GreaseField {
                value_offset: p,
                data_offset: if kex_len > 0 { Some(kex_start) } else { None },
                data_size: if kex_len > 0 { Some(kex_len) } else { None },
            });
        } else if result.is_none() {
            result = Some(FieldOffset {
                offset: kex_start,
                size: kex_len,
            });
        }

        p = kex_start + kex_len;
    }

    let key_share =
        result.ok_or_else(|| anyhow::anyhow!("no non-GREASE key exchange entry in key_share"))?;
    Ok((key_share, grease))
}

fn parse_psk(
    raw: &[u8],
    ext_data: usize,
    ext_len: usize,
) -> Result<(FieldOffset, FieldOffset, FieldOffset)> {
    ensure!(ext_len >= 2, "psk extension too short");
    let end = ext_data + ext_len;

    let ids_len = u16::from_be_bytes([raw[ext_data], raw[ext_data + 1]]) as usize;
    let p = ext_data + 2;

    ensure!(p + 2 <= end, "psk identity truncated");
    let id_len = u16::from_be_bytes([raw[p], raw[p + 1]]) as usize;

    let psk_identity = FieldOffset {
        offset: p + 2,
        size: id_len,
    };
    let ticket_age = FieldOffset {
        offset: p + 2 + id_len,
        size: 4,
    };

    let binders_start = ext_data + 2 + ids_len;
    ensure!(binders_start + 3 <= end, "psk binders truncated");

    let binder_len = raw[binders_start + 2] as usize;
    ensure!(
        binders_start + 3 + binder_len <= end,
        "psk binder truncated"
    );

    let psk_binder = FieldOffset {
        offset: binders_start + 3,
        size: binder_len,
    };

    Ok((psk_identity, ticket_age, psk_binder))
}
