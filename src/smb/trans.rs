use bitflags::bitflags;
use bytes::{Bytes, Buf, BytesMut, BufMut};

use crate::win::NotifyAction;
use crate::utils;
use super::Error;

/// Specification of a Subcommand that can be used in msg::Transact messages
pub trait SubCmd {
    const ID: u16;
    const MAX_SETUP_COUNT: u8;
    const MAX_PARAM_COUNT: u32;
    const MAX_DATA_COUNT: u32;


    fn setup(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }

    fn parameter(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }

    fn data(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }
}

pub trait SubReply: Sized {
    const ID: u16;

    fn parse(setup: Bytes, parameter: Bytes, data: Bytes) -> Result<Self, Error>;
}



/// NT_TRANSACT_NOTIFY_CHANGE Subcommand for msg::Transact, see 2.2.7.4:
/// This command notifies the client of anything that changed in the directory
/// given by fid. The command is single-shot and must be resend for getting more
/// changes.
pub struct NotifySetup {
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

impl SubCmd for NotifySetup {
    const ID: u16 = 4;
    const MAX_SETUP_COUNT: u8 = 0;
    const MAX_PARAM_COUNT: u32 = 1000;
    const MAX_DATA_COUNT: u32 = 0;

    fn setup(&self) -> Result<Bytes, Error> {
        let mut parameter = BytesMut::with_capacity(8);
        parameter.put_u32_le(self.mode.bits());
        parameter.put_u16_le(self.fid);
        parameter.put_u8(if self.recursive { 1 } else { 0 });
        parameter.put_u8(0);
        Ok(parameter.freeze())
    }
}

/// Response to NT_TRANSACT_NOTIFY_CHANGE Subcommand, the format of the
/// reply is documented in [MS-FSCC] section 2.4.42.
pub struct Notification {
    pub changes: Vec<(String, NotifyAction)>,
}

impl Notification {
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


impl SubReply for Notification {
    const ID: u16 = 4;

    fn parse(_setup: Bytes, parameter: Bytes, _data: Bytes) -> Result<Self, Error> {
        let mut changes = Vec::new();
        let mut start = 0;

        loop {
            let mut parser = parameter.slice(start..);
            if parser.len() == 0 {
                break;
            }
            if parser.len() < 4 {
                return Err(Error::InvalidData);
            }

            let next = parser.get_u32_le() as usize;
            changes.push(Self::parse_notify_info(parser)?);

            if next == 0 {
                break;
            }
            start += next;
        }

        Ok(Self { changes })
    }
}
