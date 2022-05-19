pub(crate) mod msg;
pub(crate) mod reply;
pub(crate) mod subcmd;
pub(crate) mod subreply;
pub(crate) mod collector;

use bytes::Bytes;
use super::Error;

pub(crate) trait SubCmd {
    const SETUP: u16;
    const MAX_SETUP_COUNT: u8;
    const MAX_PARAM_COUNT: u16;
    const MAX_DATA_COUNT: u16;

    fn parameter(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }

    fn data(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }
}


pub(crate) trait SubReply: Sized {
    const SETUP: u16;

    fn parse(parameter: Bytes, data: Bytes) -> Result<Self, Error>;
}
