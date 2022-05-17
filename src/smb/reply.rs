use bytes::{Bytes, Buf};

use crate::utils;
use crate::win::*;

use super::Error;
use super::common::*;
use super::info::*;
use super::{trans, trans2};

/// Helper struct holding all relevant information of a reply
/// to be used by create() method.
pub struct ReplyCtx {
    info: Info,

    parameter: Bytes,

    data: Bytes,
    data_offset: usize,
}


pub trait Reply: Sized {
    const CMD: Cmd;
    const ANDX: bool;

    fn create(ctx: ReplyCtx) -> Result<Self, Error>;

    fn parse(info: Info, mut buffer: Bytes) -> Result<Self, Error> {
        let parameter_count = buffer.get_u8() as usize;
        let parameter_offset = SMB_HEADER_LEN + 1;
        let mut parameter = buffer.copy_to_bytes(2*parameter_count);

        let data_count = buffer.get_u16_le() as usize;
        let data_offset = parameter_offset + 2*parameter_count + 2;
        let data = buffer.copy_to_bytes(data_count);

        // first parameter is AndX structure, if this command has one
        if Self::ANDX {
            if AndX::parse(&mut parameter)?.is_some() {
                return Err(Error::Unsupported("AndX chaining is currently not supported".to_owned()));
            }
        }

        let ctx = ReplyCtx {
            info,
            parameter,
            data,
            data_offset,
        };


        Self::create(ctx)
    }
}


#[derive(Debug)]
pub struct ServerSetup {
    pub dialect: usize,
    pub security_mode: u8,
    pub max_mpx_count: u16,
    pub max_number_vcs: u16,
    pub max_buffer_size: u32,
    pub max_raw_size: u32,
    pub session_key: u32,
    pub capabilities: Capabilities,
    pub system_time: u64,
    pub timezone: u16,
    pub challenge_length: u8,
    pub server_guid: Bytes,
}

impl Reply for ServerSetup {
    const CMD: Cmd = Cmd::Negotiate;
    const ANDX: bool = false;

    fn create(ctx: ReplyCtx) -> Result<Self, Error> {
        // strictly there may only be one word, but we only support dialects above
        // NTLM 0.12 and therefor need at least 17 words.
        if ctx.parameter.len() < 17 {
            return Err(Error::Unsupported("negotiate header with too few parameter".to_owned()));
        }


        // parse parameter
        let mut parameter = ctx.parameter;

        // this must always be here (0xffff means no supported dialects)
        let dialect = parameter.get_u16_le() as usize;
        if dialect == 0xffff {
            return Err(Error::NoDialect);
        }
        if SMB_SUPPORTED_DIALECTS.get(dialect).is_none() {
            return Err(Error::InvalidHeader);
        }


        let security_mode = parameter.get_u8();
        let max_mpx_count = parameter.get_u16_le();
        let max_number_vcs = parameter.get_u16_le();
        let max_buffer_size = parameter.get_u32_le();
        let max_raw_size = parameter.get_u32_le();
        let session_key = parameter.get_u32_le();
        let capabilities = Capabilities::from_bits_truncate(parameter.get_u32_le());
        let system_time = parameter.get_u64_le();
        let timezone = parameter.get_u16_le();
        let challenge_length = parameter.get_u8();


        //
        // Now parse data
        //
        let mut data = ctx.data;
        if data.len() < 16 {
            return Err(Error::InvalidData);
        }

        let server_guid = data.copy_to_bytes(16);


        let reply = Self {
            dialect,
            security_mode,
            max_mpx_count,
            max_number_vcs,
            max_buffer_size,
            max_raw_size,
            session_key,
            capabilities,
            system_time,
            timezone,
            challenge_length,
            server_guid,
        };

        Ok(reply)
    }
}


/// SessionSetup is used for challenge-response authentication
#[derive(Debug)]
pub struct SessionSetup {
    pub guest_mode: bool,
    pub security_blob: Bytes,
    pub uid: u16,
}

impl Reply for SessionSetup {
    const CMD: Cmd = Cmd::SessionSetup;
    const ANDX: bool = true;

    fn create(ctx: ReplyCtx) -> Result<Self, Error> {
        // parse parameter
        let mut parameter = ctx.parameter;
        let action = parameter.get_u16_le();
        let blob_length = parameter.get_u16_le() as usize;

        // parse data
        let mut data = ctx.data;
        let blob = data.copy_to_bytes(blob_length);

        // these two maybe unicode or ascii depending on flags2
        //let os_name = read_unicode_str0(&mut data);
        //let lanman = read_unicode_str0(&mut data);

        // build reply
        let reply = SessionSetup {
            guest_mode: action & 0x0001 == 1,
            security_blob: blob,
            uid: ctx.info.uid,
        };

        Ok(reply)
    }
}


/// Share is returned by TreeConnect command and represents a mounted
/// SMB share.
///
/// Every further file operation needs such a Share to know in which filesystem
/// it should operate. For example to generate a file or directory handle (see
/// 'Handle' below) a Share must be given.
/// (But Handle itself saves the neccassary information, so an operation
/// using a Handle does not also need a Share.)
///
/// This type is given out to the user.
///
#[derive(Debug)]
pub struct Share {
    pub access_rights: DirAccessMask,
    pub guest_rights: DirAccessMask,
    pub service: String,
    pub filesystem: String,
    pub tid: u16,
}


impl Reply for Share {
    const CMD: Cmd = Cmd::TreeConnect;
    const ANDX: bool = true;

    fn create(ctx: ReplyCtx) -> Result<Self, Error> {
        // parameter
        let mut parameter = ctx.parameter;
        parameter.advance(2);       // ignore optional support
        let access_rights = DirAccessMask::from_bits_truncate(parameter.get_u32_le());
        let guest_rights = DirAccessMask::from_bits_truncate(parameter.get_u32_le());

        // data
        let mut data = ctx.data;
        let service = utils::parse_str_0(&mut data)?;

        let filesystem = if ctx.info.flags2.contains(Flags2::UNICODE) {
            // skip one byte padding
            if service.len() % 2 == 1 {
                data.advance(1);
            }
            utils::parse_utf16le_0(&mut data)
        } else {
            utils::parse_str_0(&mut data)
        }?;

        let reply = Self {
            access_rights,
            guest_rights,
            service,
            filesystem,
            tid: ctx.info.tid,
        };

        Ok(reply)
    }
}


/// Reply for COM_TREE_DISCONNECT message
pub struct TreeDisconnect;

impl Reply for TreeDisconnect {
    const CMD: Cmd = Cmd::TreeDisconnect;
    const ANDX: bool = false;

    fn create(_ctx: ReplyCtx) -> Result<Self, Error> {
        Ok(Self)
    }
}




/// Handle is the struct returned by 'Create' SMB message and represents
/// an opened file or directory. File and directory opererations will
/// need such a Handle to work.
///
/// This type is given out to the user.
///
#[derive(Debug)]
pub struct Handle {
    pub tid: u16,
    pub fid: u16,
    pub oplock: OpLockLevel,
    pub disposition: CreateDisposition,
    pub create_time: u64,
    pub access_time: u64,
    pub write_time: u64,
    pub change_time: u64,
    pub attributes: ExtFileAttr,
    pub allocation_size: u64,
    pub size: u64,
    pub file_type: ResourceType,
    pub directory: bool,
}

impl Reply for Handle {
    const CMD: Cmd = Cmd::Create;
    const ANDX: bool = true;

    fn create(ctx: ReplyCtx) -> Result<Self, Error> {
        // parameter
        let mut parameter = ctx.parameter;
        let oplock = OpLockLevel::from_bits_truncate(parameter.get_u8());
        let fid = parameter.get_u16_le();
        let disposition = CreateDisposition::from_bits_truncate(parameter.get_u32_le());

        let create_time = parameter.get_u64_le();
        let access_time = parameter.get_u64_le();
        let write_time = parameter.get_u64_le();
        let change_time = parameter.get_u64_le();

        let attributes = ExtFileAttr::from_bits_truncate(parameter.get_u32_le());
        let allocation_size = parameter.get_u64_le();
        let size = parameter.get_u64_le();
        let file_type = ResourceType::from_bits_truncate(parameter.get_u16_le());

        parameter.advance(2);       // ignore 2 byte pipe status
        let directory = match parameter.get_u8() {
            0 => false,
            1 => true,

            _ => return Err(Error::InvalidData),
        };


        let reply = Self {
            tid: ctx.info.tid,
            fid,
            oplock,
            disposition,
            create_time,
            access_time,
            write_time,
            change_time,
            attributes,
            allocation_size,
            size,
            file_type,
            directory,
        };

        Ok(reply)
    }
}


/// SMB_COM_CLOSE Message (does not contain any information).
pub struct Close;

impl Reply for Close {
    const CMD: Cmd = Cmd::Close;
    const ANDX: bool = false;

    fn create(_ctx: ReplyCtx) -> Result<Self, Error> {
        Ok(Self)
    }
}


/// reply to SMB_COM_READ_ANDX message
pub struct Read {
    pub data: Bytes,
}

impl Reply for Read {
    const CMD: Cmd = Cmd::Read;
    const ANDX: bool = true;


    fn create(ctx: ReplyCtx) -> Result<Self, Error> {
        // parameter
        let mut parameter = ctx.parameter;
        parameter.advance(2);   // available (only for pipes)
        parameter.advance(2);   // data compaction (reserved, should be 0)
        parameter.advance(2);   // more reserved

        let length = parameter.get_u16_le() as usize;

        // more reserved parameter...


        // data
        let mut data = ctx.data;
        // skip 1 byte of optional padding
        if data.remaining() > length {
            data.advance(1);
        }
        // now everything should fit or we bail
        if data.remaining() != length {
            return Err(Error::InvalidData);
        }

        let file_data = data.copy_to_bytes(length);

        Ok(Read { data: file_data })
    }
}


/// Reply to SMB_COM_DELETE (0x06), see 2.2.4.7 in CIFS
pub struct Delete;

impl Reply for Delete {
    const CMD: Cmd = Cmd::Delete;
    const ANDX: bool = false;

    fn create(_ctx: ReplyCtx) -> Result<Self, Error> {
        Ok(Self)
    }
}

/// Reply to SMB_COM_DELETE_DIRECTORY (0x01), see 2.2.4.2 in CIFS
pub struct Rmdir;

impl Reply for Rmdir {
    const CMD: Cmd = Cmd::Rmdir;
    const ANDX: bool = false;

    fn create(_ctx: ReplyCtx) -> Result<Self, Error> {
        Ok(Self)
    }
}


/// Reply to SMB_COM_NT_TRANSACT, see 2.2.4.62.2
pub struct Transact<T> {
    pub subcmd: T,
}

impl<T: trans::SubReply> Reply for Transact<T> {
    const CMD: Cmd = Cmd::Transact;
    const ANDX: bool = false;

    fn create(mut ctx: ReplyCtx) -> Result<Self, Error> {
        // parameter
        ctx.parameter.advance(3);
        let total_parameter_count = ctx.parameter.get_u32_le() as usize;
        let total_data_count = ctx.parameter.get_u32_le() as usize;

        let parameter_count = ctx.parameter.get_u32_le() as usize;
        let raw_parameter_offset = ctx.parameter.get_u32_le() as usize;
        let _parameter_displacement = ctx.parameter.get_u32_le();

        let data_count = ctx.parameter.get_u32_le() as usize;
        let raw_data_offset = ctx.parameter.get_u32_le() as usize;
        let _data_displacement = ctx.parameter.get_u32_le();

        let setup_words = ctx.parameter.get_u8() as usize;
        let sub_setup = ctx.parameter.copy_to_bytes(2*setup_words);

        if parameter_count < total_parameter_count || data_count < total_data_count {
            return Err(Error::Unsupported("transaction message split to multiple packets".to_owned()));
        }

        // data
        let sub_parameter = if parameter_count > 0 {
            let offset = utils::try_sub(raw_parameter_offset, ctx.data_offset)
                .ok_or(Error::InvalidData)?;

            ctx.data.slice(offset..offset+parameter_count)
        } else {
            Bytes::new()
        };

        let sub_data = if data_count > 0 {
            let offset = utils::try_sub(raw_data_offset, ctx.data_offset)
                .ok_or(Error::InvalidData)?;

            ctx.data.slice(offset..offset+data_count)
        } else {
            Bytes::new()
        };

        // create sub-command response
        let subcmd = T::parse(sub_setup, sub_parameter, sub_data)?;

        Ok(Transact::<T> { subcmd })
    }
}


/// Reply to SMB_COM_TRANSACTION2, see 2.2.4.46.2
pub struct Transact2<T> {
    pub subcmd: T,
}

impl<T: trans2::SubReply> Reply for Transact2<T> {
    const CMD: Cmd = Cmd::Transact2;
    const ANDX: bool = false;

    fn create(mut ctx: ReplyCtx) -> Result<Self, Error> {
        // parameter
        let total_parameter_count = ctx.parameter.get_u16_le() as usize;
        let total_data_count = ctx.parameter.get_u16_le() as usize;
        ctx.parameter.advance(2);   // reserved

        let parameter_count = ctx.parameter.get_u16_le() as usize;
        let parameter_offset = utils::try_sub(ctx.parameter.get_u16_le().into(), ctx.data_offset)
            .ok_or(Error::InvalidData)?;
        ctx.parameter.advance(2);   // ignoring parameter displacement

        let data_count = ctx.parameter.get_u16_le() as usize;
        let data_offset = utils::try_sub(ctx.parameter.get_u16_le().into(), ctx.data_offset)
            .ok_or(Error::InvalidData)?;
        ctx.parameter.advance(2);   // ignoring data displacement


        // FIXME we need to support incomplete transact2 replies
        if parameter_count < total_parameter_count || data_count < total_data_count {
            return Err(Error::Unsupported("transaction2 reply split to multiple packets".to_owned()));
        }

        // data
        let sub_parameter = ctx.data.slice(parameter_offset..parameter_offset+parameter_count);
        let sub_data = ctx.data.slice(data_offset..data_offset+data_count);

        // create sub-command response
        let subcmd = T::parse(sub_parameter, sub_data)?;

        Ok(Transact2::<T> { subcmd })
    }
}




#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use hex_literal::hex;
    use super::*;

    #[test]
    fn parse_negotiate() {
        let buffer = BytesMut::from(hex!(
                "1100000310000100041100000000010000000000fde300808e6db6b79b3ed801"
                "0000001000f9fe3c88bf27b444bd3d74f7b2fdbf01").as_ref()).freeze();

        // makeup header info, since parsing may depend on that data
        let info = Info::default(Cmd::Negotiate);

        // Negotiate returns a ServerSetup
        let reply = ServerSetup::parse(&info, buffer)
            .expect("can't parse negotiate body");

        // check reply
        assert_eq!(reply.dialect, 0);
        assert_eq!(reply.security_mode, 3);
        assert_eq!(reply.max_mpx_count, 16);
        assert_eq!(reply.max_number_vcs, 1);
        assert_eq!(reply.max_buffer_size, 4356);
        assert_eq!(reply.session_key, 0);
        assert_eq!(reply.capabilities, Capabilities::EXTENDED_SECURITY
                                     | Capabilities::INFOLEVEL_PASS
                                     | Capabilities::LARGE_READX
                                     | Capabilities::LARGE_WRITEX
                                     | Capabilities::NT_FIND
                                     | Capabilities::LOCK_AND_READ
                                     | Capabilities::LEVEL2_OPLOCKS
                                     | Capabilities::NTSTATUS
                                     | Capabilities::REMOTE_APIS
                                     | Capabilities::NT_SMBS
                                     | Capabilities::LARGE_FILES
                                     | Capabilities::UNICODE
                                     | Capabilities::RAW_MODE);

        assert_eq!(reply.system_time, 0x01d83e9bb7b66d8e);// FIXME implement windows time type
        assert_eq!(reply.timezone, 0);
        assert_eq!(reply.challenge_length, 0);
        assert_eq!(&reply.server_guid[..], hex!("f9fe3c88bf27b444bd3d74f7b2fdbf01"));
    }


    #[test]
    fn parse_session_setup() {
        let blob = hex!(
            "04ff002d010000b80002014e544c4d5353500002000000140014003800000015"
            "828ae2d9102a72d8b439d200000000000000006c006c004c0000000501280a00"
            "00000f4b0049004500460045004c002d00490050004300020014004b00490045"
            "00460045004c002d00490050004300010014004b0049004500460045004c002d"
            "00490050004300040014004b0049004500460045004c002d0049005000430003"
            "0014004b0049004500460045004c002d00490050004300060004000100000000"
            "00000000570069006e0064006f0077007300200035002e003100000057006900"
            "6e0064006f00770073002000320030003000300020004c0041004e0020004d00"
            "61006e00610067006500720000");

        let buffer = BytesMut::from(&blob[..]).freeze();

        let info = Info::default(Cmd::Negotiate);
        let reply = SessionSetup::parse(&info, buffer)
            .expect("can't parse SessionSetup");

        assert_eq!(reply.guest_mode, false);
        assert_eq!(reply.security_blob.as_ref(), hex!(
            "4e544c4d5353500002000000140014003800000015828ae2d9102a72"
            "d8b439d200000000000000006c006c004c0000000501280a0000000f"
            "4b0049004500460045004c002d00490050004300020014004b004900"
            "4500460045004c002d00490050004300010014004b00490045004600"
            "45004c002d00490050004300040014004b0049004500460045004c00"
            "2d00490050004300030014004b0049004500460045004c002d004900"
            "50004300060004000100000000000000"));
    }
}
