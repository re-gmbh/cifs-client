use std::fmt;

use crate::smb;
use crate::ntlm;
use crate::smb::info::{Status, Cmd};


#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    SMBError(smb::Error),
    NTLMError(ntlm::Error),
    InternalError(String),
    InvalidFrameType(u8),
    InvalidFrame,
    UnexpectedEOF,
    FrameTooBig,
    UnexpectedReply(Cmd, Cmd),
    TooManyReplies(usize),
    ServerError(Status),
    Unsupported(String),
    InvalidUri,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(what) => write!(f, "io error: {}", what),
            Error::SMBError(err) => write!(f, "protocol error: {}", err),
            Error::NTLMError(err) => write!(f, "NTLM error: {}", err),
            Error::InternalError(what) => write!(f, "internal error: {}", what),
            Error::InvalidFrameType(v) => write!(f, "invalid NetBIOS message type: {:02x}", v),
            Error::InvalidFrame => write!(f, "invalid NetBIOS frame"),
            Error::UnexpectedEOF => write!(f, "unexpected end of stream"),
            Error::FrameTooBig => write!(f, "frame exceeds maximal size"),
            Error::UnexpectedReply(want,got) => write!(f, "unexpected reply, want: {:?}, got: {:?}", want, got),
            Error::TooManyReplies(num) => write!(f, "we expect one reply but got {}", num),
            Error::ServerError(status) => write!(f, "server reports error: {}", status),
            Error::Unsupported(what) => write!(f, "unsupported feature: {}", what),
            Error::InvalidUri => write!(f, "URI is invalid"),
        }
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Self {
        Error::InternalError(format!("numeric conversion failed: {}", err))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
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
