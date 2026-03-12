mod bridge;
mod conn;
pub mod disguise;

pub use bridge::bridge;
pub use conn::{accept, dial, new_tcp_socket};
pub use disguise::tls::FakeTlsStream;
