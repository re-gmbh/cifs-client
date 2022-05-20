use std::fmt;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

use num_enum::TryFromPrimitiveError;

use crate::utils;
use super::info::Cmd;


#[derive(Debug)]
pub enum Error {
    InvalidHeader,
    InvalidData,
    InvalidCommand(u8),
    NoDialect,
    NeedSecurityExt,
    ReplyExpected,
    CreatePackage(String),
    Reassemble(String),
    Unsupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidHeader => write!(f, "invalid header"),
            Error::InvalidData => write!(f, "invalid packet data"),
            Error::InvalidCommand(cmd) => write!(f, "invalid command: {:02x}", cmd),
            Error::NoDialect => write!(f, "no supported dialect found"),
            Error::NeedSecurityExt => write!(f, "need security extension"),
            Error::ReplyExpected => write!(f, "header is marked as request instead of reply"),
            Error::CreatePackage(whatnow) => write!(f, "error creating package: {}", whatnow),
            Error::Reassemble(desc) => write!(f, "error reassembling transact2 reply: {}", desc),
            Error::Unsupported(what) => write!(f, "unsupported feature: {}", what),
        }
    }
}

impl From<TryFromPrimitiveError<Cmd>> for Error {
    fn from(err: TryFromPrimitiveError<Cmd>) -> Self {
        Error::InvalidCommand(err.number)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_err: FromUtf8Error) -> Self {
        Error::InvalidData
    }
}

impl From<std::char::DecodeUtf16Error> for Error {
    fn from(_err: std::char::DecodeUtf16Error) -> Self {
        Error::InvalidData
    }
}

impl From<TryFromIntError> for Error {
    fn from(_err: TryFromIntError) -> Self {
        Error::InvalidData
    }
}

impl From<utils::ParseStrError> for Error {
    fn from(_err: utils::ParseStrError) -> Self {
        Error::InvalidData
    }
}

