use std::fmt;

use crate::netbios;
use crate::smb;
use crate::ntlm;
use crate::smb::info::{Status, Cmd};


#[derive(Debug)]
pub enum Error {
    NetBios(netbios::Error),
    SMBError(smb::Error),
    NTLMError(ntlm::Error),
    InternalError(String),
    UnexpectedReply(Cmd, Cmd),
    TooManyReplies(usize),
    ServerError(Status),
    Unsupported(String),
    InvalidUri,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::NetBios(error) => write!(f, "NetBios error: {}", error),
            Error::SMBError(err) => write!(f, "protocol error: {}", err),
            Error::NTLMError(err) => write!(f, "NTLM error: {}", err),
            Error::InternalError(what) => write!(f, "internal error: {}", what),
            Error::UnexpectedReply(want,got) => write!(f, "unexpected reply, want: {:?}, got: {:?}", want, got),
            Error::TooManyReplies(num) => write!(f, "we expect one reply but got {}", num),
            Error::ServerError(status) => write!(f, "server error: {}", status),
            Error::Unsupported(what) => write!(f, "unsupported feature: {}", what),
            Error::InvalidUri => write!(f, "URI is invalid"),
        }
    }
}

impl From<netbios::Error> for Error {
    fn from(err: netbios::Error) -> Self {
        Error::NetBios(err)
    }
}

impl From<smb::Error> for Error {
    fn from(err: smb::Error) -> Self {
        Error::SMBError(err)
    }
}

impl From<ntlm::Error> for Error {
    fn from(err: ntlm::Error) -> Self {
        Error::NTLMError(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Self {
        Error::InternalError(format!("numeric conversion failed: {}", err))
    }
}
