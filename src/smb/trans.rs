use bitflags::bitflags;
use bytes::{Bytes, Buf, BytesMut, BufMut};

use crate::win::NotifyAction;
use crate::utils;
use super::common::Error;

/// Specification of a Subcommand that can be used in the Transact message
/// below
pub(crate) trait TransCmd {
    const ID: u16;
    const MAX_SETUP_COUNT: u8;
    const MAX_PARAM_COUNT: u32;
    const MAX_DATA_COUNT: u32;


    fn setup(&self) -> Bytes {
        Bytes::new()
    }

    fn parameter(&self) -> Bytes {
        Bytes::new()
    }

    fn data(&self) -> Bytes {
        Bytes::new()
    }
}

pub(crate) trait TransReply: Sized {
    const ID: u16;

    fn parse(setup: Bytes, parameter: Bytes, data: Bytes) -> Result<Self, Error>;
}



/// Notify Subcommand for Transact
pub(crate) struct NotifySetup {
    fid: u16,
    recursive: bool,
    mode: NotifyMode,
}

bitflags! {
    pub struct NotifyMode: u32 {
        const FILENAME          = 0x00000001;
        const DIRNAME           = 0x00000002;
        const NAME              = 0x00000003;
        const ATTR              = 0x00000004;
        const SIZE              = 0x00000008;
        const LAST_WRITE        = 0x00000010;
        const LAST_ACCESS       = 0x00000020;
        const CREATION          = 0x00000040;
        const EA                = 0x00000080;
        const SECURITY          = 0x00000100;
        const STREAM_NAME       = 0x00000200;
        const STREAM_SIZE       = 0x00000400;
        const STREAM_WRITE      = 0x00000800;
    }
}


impl NotifySetup {
    pub fn new(fid: u16, mode: NotifyMode, recursive: bool) -> Self {
        Self {
            fid,
            recursive,
            mode,
        }
    }
}

impl TransCmd for NotifySetup {
    const ID: u16 = 4;
    const MAX_SETUP_COUNT: u8 = 0;
    const MAX_PARAM_COUNT: u32 = 1000;
    const MAX_DATA_COUNT: u32 = 0;

    fn setup(&self) -> Bytes {
        let mut parameter = BytesMut::with_capacity(8);
        parameter.put_u32_le(self.mode.bits());
        parameter.put_u16_le(self.fid);
        parameter.put_u8(if self.recursive { 1 } else { 0 });
        parameter.put_u8(0);
        parameter.freeze()
    }
}

/// Response to Notify Subcommand
pub(crate) struct NotifyResponse {
    pub changes: Vec<(String, NotifyAction)>,
}

impl NotifyResponse {
    /// Private method that helps parsing the
    fn parse_notify_info(mut buffer: Bytes) -> Result<(String, NotifyAction), Error> {
        if buffer.len() < 8 {
            return Err(Error::InvalidData);
        }

        let action = buffer.get_u32_le()
                           .try_into()
                           .map_err(|_| Error::InvalidData)?;

        let filename_length = buffer.get_u32_le() as usize;

        if buffer.remaining() < filename_length {
            return Err(Error::InvalidData);
        }

        let raw_filename = buffer.copy_to_bytes(filename_length);
        let filename = utils::decode_utf16le(raw_filename.as_ref())?;

        Ok((filename, action))
    }
}


impl TransReply for NotifyResponse {
    const ID: u16 = 4;

    fn parse(_setup: Bytes, parameter: Bytes, _data: Bytes) -> Result<Self, Error> {
        let mut changes = Vec::new();
        let mut start = 0;

        loop {
            let mut parser = parameter.slice(start..);
            if parser.len() < 4 {
                return Err(Error::InvalidData);
            }

            let next = parser.get_u32_le() as usize;

            changes.push(Self::parse_notify_info(parser)?);

            if next == 0 {
                break;
            }
            if next <= start || next >= parameter.len() {
                return Err(Error::InvalidData);
            }
            start = next;
        }

        Ok(Self { changes })
    }
}
