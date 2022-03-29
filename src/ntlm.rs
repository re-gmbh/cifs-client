mod error;
mod buffer;
mod packet;
mod auth;
mod init;
mod challenge;

pub use error::Error;
pub use auth::Auth;
pub use challenge::ChallengeMsg;
pub use init::{Flags, Version, InitMsg};


const NTLMSSP_MAGIC: &[u8] = b"NTLMSSP\0";
const NTLM_MSG_INIT: u32 = 1;
const NTLM_MSG_CHALLENGE: u32 = 2;
const NTLM_MSG_RESPONSE: u32 = 3;
const NTLM_REVISION: u8 = 15;
