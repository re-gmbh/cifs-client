#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]


pub mod connection;
pub mod error;
pub mod ntlm;
mod smb;
mod utils;

// re-export important types directly in crate-root
pub use error::Error;
pub use ntlm::Auth;
pub use connection::Cifs;
