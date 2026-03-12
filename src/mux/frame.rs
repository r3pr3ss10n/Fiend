pub const CMD_SYN: u8 = 0;
pub const CMD_FIN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_NOP: u8 = 3;
pub const CMD_UPD: u8 = 4;

pub const HEADER_SIZE: usize = 8;
pub const SZ_CMD_UPD: usize = 8;
pub const INITIAL_PEER_WINDOW: u32 = 8_388_608;

pub fn encode_header(buf: &mut [u8], ver: u8, cmd: u8, sid: u32, length: u16) {
    buf[0] = ver;
    buf[1] = cmd;
    buf[2..4].copy_from_slice(&length.to_le_bytes());
    buf[4..8].copy_from_slice(&sid.to_le_bytes());
}

pub fn decode_header(buf: &[u8; HEADER_SIZE]) -> (u8, u8, u16, u32) {
    (
        buf[0],
        buf[1],
        u16::from_le_bytes([buf[2], buf[3]]),
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    )
}

pub fn encode_upd(buf: &mut [u8; SZ_CMD_UPD], consumed: u32, window: u32) {
    buf[0..4].copy_from_slice(&consumed.to_le_bytes());
    buf[4..8].copy_from_slice(&window.to_le_bytes());
}

pub fn decode_upd(buf: &[u8; SZ_CMD_UPD]) -> (u32, u32) {
    (
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    )
}
