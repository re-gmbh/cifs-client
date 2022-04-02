use bytes::{Bytes, Buf};

use crate::utils;
use crate::win::*;
use super::common::*;
use super::trans::TransReply;

pub trait Reply: Sized {
    const CMD: RawCmd;
    const ANDX: bool;

    fn parse_param(info: &Info, parameter: Bytes, data: Bytes) -> Result<Self, Error>;

    fn parse(info: &Info, buffer: &mut Bytes) -> Result<Self, Error> {
        let parameter_count = buffer.get_u8() as usize;
        let mut parameter = buffer.copy_to_bytes(2*parameter_count);

        let data_count = buffer.get_u16_le() as usize;
        let data = buffer.copy_to_bytes(data_count);

        // first parameter is AndX structure, if this command has one
        if Self::ANDX {
            if AndX::parse(&mut parameter)?.is_some() {
                return Err(Error::Unsupported("AndX chaining is currently not supported".to_owned()));
            }
        }

        Self::parse_param(info, parameter, data)
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
    const CMD: RawCmd = RawCmd::Negotiate;
    const ANDX: bool = false;

    fn parse_param(_info: &Info, mut parameter: Bytes, mut data: Bytes)
        -> Result<Self, Error>
    {
        // strictly there may only be one word, but we only support dialects above
        // NTLM 0.12 and therefor need at least 17 words.
        if parameter.len() < 17 {
            return Err(Error::Unsupported("negotiate header with too few parameter".to_owned()));
        }

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
    const CMD: RawCmd = RawCmd::SessionSetup;
    const ANDX: bool = true;

    fn parse_param(info: &Info, mut parameter: Bytes, mut data: Bytes)
        -> Result<Self, Error>
    {
        // parse parameter
        let action = parameter.get_u16_le();
        let blob_length = parameter.get_u16_le() as usize;

        // parse data
        let blob = data.copy_to_bytes(blob_length);

        // these two maybe unicode or ascii depending on flags2
        //let os_name = read_unicode_str0(&mut data);
        //let lanman = read_unicode_str0(&mut data);

        // build reply
        let reply = SessionSetup {
            guest_mode: action & 0x0001 == 1,
            security_blob: blob,
            uid: info.uid,
        };

        Ok(reply)
    }
}


/// Share is the DataType returned by TreeConnect command
#[derive(Debug)]
pub struct Share {
    pub access_rights: DirAccessMask,
    pub guest_rights: DirAccessMask,
    pub service: String,
    pub filesystem: String,
    pub tid: u16,
}


impl Reply for Share {
    const CMD: RawCmd = RawCmd::TreeConnect;
    const ANDX: bool = true;

    fn parse_param(info: &Info, mut parameter: Bytes, mut data: Bytes)
        -> Result<Self, Error>
    {
        // parameter
        parameter.advance(2);       // ignore optional support
        let access_rights = DirAccessMask::from_bits_truncate(parameter.get_u32_le());
        let guest_rights = DirAccessMask::from_bits_truncate(parameter.get_u32_le());

        // data
        let service = utils::parse_str_0(&mut data)?;

        let filesystem = if info.flags2.contains(Flags2::UNICODE) {
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
            tid: info.tid,
        };

        Ok(reply)
    }
}


/// Reply for COM_TREE_DISCONNECT message
pub struct TreeDisconnect {}

impl Reply for TreeDisconnect {
    const CMD: RawCmd = RawCmd::TreeDisconnect;
    const ANDX: bool = false;

    fn parse_param(_info: &Info, _parameter: Bytes, _data: Bytes)
        -> Result<Self, Error>
    {
        Ok(Self {})
    }
}





/// FileHandle is the struct returned by 'Create' SMB message
#[derive(Debug)]
pub struct FileHandle {
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

impl Reply for FileHandle {
    const CMD: RawCmd = RawCmd::Create;
    const ANDX: bool = true;

    fn parse_param(info: &Info, mut parameter: Bytes, _data: Bytes)
        -> Result<Self, Error>
    {
        // parameter
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
            tid: info.tid,
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


/// SMB Close Message (does not return anything)
pub struct Close {}

impl Reply for Close {
    const CMD: RawCmd = RawCmd::Close;
    const ANDX: bool = false;

    fn parse_param(_info: &Info, _parameter: Bytes, _data: Bytes)
        -> Result<Self, Error>
    {
        Ok(Self {})
    }
}


/// reply to a SMB Read message
pub struct Read {
    pub data: Bytes,
}

impl Reply for Read {
    const CMD: RawCmd = RawCmd::Read;
    const ANDX: bool = true;


    fn parse_param(_info: &Info, mut parameter: Bytes, mut data: Bytes)
        -> Result<Self, Error>
    {
        // parameter
        parameter.advance(2);   // available (only for pipes)
        parameter.advance(2);   // data compaction (reserved, should be 0)
        parameter.advance(2);   // more reserved

        let length = parameter.get_u16_le() as usize;

        // more reserved parameter...


        // data

        // skip 1 byte of optional padding
        if data.remaining() > length {
            data.advance(1);
        }
        // now everything should fit or we bail
        if data.remaining() != length {
            return Err(Error::InvalidData);
        }

        let file_data = data.copy_to_bytes(length);

        let read = Read {
            data: file_data,
        };

        Ok(read)
    }
}

/// Reply to SMB_COM_NT_TRANSACT
pub struct Transact<T> {
    pub subcmd: T,
}

impl<T: TransReply> Reply for Transact<T> {
    const CMD: RawCmd = RawCmd::Transact;
    const ANDX: bool = false;

    fn parse_param(_info: &Info, mut parameter: Bytes, mut data: Bytes)
        -> Result<Self, Error>
    {
        let parameter_len = parameter.len();

        // parameter
        parameter.advance(3);
        let total_parameter_count = parameter.get_u32_le() as usize;
        let total_data_count = parameter.get_u32_le() as usize;
        let parameter_count = parameter.get_u32_le() as usize;
        let _parameter_offset = parameter.get_u32_le();
        let _parameter_displacement = parameter.get_u32_le();
        let data_count = parameter.get_u32_le() as usize;
        let _data_offset = parameter.get_u32_le();
        let _data_displacement = parameter.get_u32_le();
        let setup_words = parameter.get_u8() as usize;
        let sub_setup = parameter.copy_to_bytes(2*setup_words);

        if parameter_count < total_parameter_count || data_count < total_data_count {
            return Err(Error::Unsupported("transaction message split to multiple packets".to_owned()));
        }

        // data
        let data_start = SMB_HEADER_LEN + 1 + parameter_len + 2;


        let sub_parameter = if parameter_count > 0 {
            data.advance((4 - (data_start % 4)) % 4);
            data.copy_to_bytes(parameter_count)
        } else {
            Bytes::new()
        };

        let sub_data = if data_count > 0 {
            data.advance((4 - ((data_start + sub_parameter.len()) % 4)) % 4);
            data.copy_to_bytes(data_count)
        } else {
            Bytes::new()
        };

        // create sub-command response
        let subcmd = T::parse(sub_setup, sub_parameter, sub_data)?;

        // create response
        let response = Self {
            subcmd,
        };

        Ok(response)
    }
}





/// Parse buffer into a specific reply. This is our normal use case, because
/// after sending a command we expect a response to this specific command.
///
/// On the other hand CIFS is free to send any response it likes (ie out of order,
/// or multiple responses chained together, ...), so this is not the most robust
/// approach.
pub(crate) fn parse<T: Reply>(mut buffer: Bytes) -> Result<T, Error> {
    // check if we have at least our SMB header?
    if buffer.remaining() < SMB_HEADER_LEN {
        return Err(Error::InvalidHeader);
    }

    // check magic
    let magic = buffer.copy_to_bytes(4);
    if &magic[..] != SMB_MAGIC {
        return Err(Error::InvalidHeader);
    }

    // check command identifier
    let cmd: RawCmd = buffer.get_u8().try_into()?;
    if cmd != T::CMD {
        return Err(Error::UnexpectedReply(T::CMD, cmd));
    }

    // info part of header
    let info = Info::parse(&mut buffer)?;

    // check status
    match info.status {
        Status::Known(NTStatus::SUCCESS) => (),
        Status::Known(NTStatus::MORE_PROCESSING) => (),

        _ => return Err(Error::ServerError(info.status)),
    }

    // this must be a reply
    if !info.flags1.contains(Flags1::REPLY) {
        return Err(Error::ReplyExpected);
    }

    // if extended_security is not set, we have to parse
    // negotiate reply differently... until we support that
    // throw an error
    if !info.flags2.contains(Flags2::EXTENDED_SECURITY) {
        return Err(Error::NeedSecurityExt);
    }

    // finally parse the expected package
    let reply = T::parse(&info, &mut buffer)?;

    Ok(reply)
}


#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use hex_literal::hex;
    use super::*;

    #[test]
    fn parse_negotiate_cmd() {
        let buffer = BytesMut::from(hex!(
                "ff534d4272000000009853c8000000000000000000000000fffffffe00000000"
                "1100000310000100041100000000010000000000fde300808e6db6b79b3ed801"
                "0000001000f9fe3c88bf27b444bd3d74f7b2fdbf01").as_ref()).freeze();

        let reply = parse::<ServerSetup>(buffer).expect("can't parse SMB blob");

        /*
        // check header infos
        assert_eq!(info.status, Status::Known(NTStatus::SUCCESS));
        assert_eq!(info.flags1, Flags1::REPLY
                              | Flags1::CASE_INSENSITIVE
                              | Flags1::CANONICAL_PATHS);

        assert_eq!(info.flags2, Flags2::UNICODE
                              | Flags2::NTSTATUS
                              | Flags2::EXTENDED_SECURITY
                              | Flags2::LONG_NAMES_USED
                              | Flags2::SIGNATURE_REQUIRED
                              | Flags2::EAS
                              | Flags2::LONG_NAMES_ALLOWED);

        assert_eq!(info.pid, 65279);
        assert_eq!(info.tid, 0xffff);
        assert_eq!(info.uid, 0);
        assert_eq!(info.mid, 0);
        */

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
        let blob = hex!("ff534d4273160000c09807c8000000000000000000000000"
                        "fffffffe0008200004ff002d010000b80002014e544c4d53"
                        "53500002000000140014003800000015828ae2d9102a72d8"
                        "b439d200000000000000006c006c004c0000000501280a00"
                        "00000f4b0049004500460045004c002d0049005000430002"
                        "0014004b0049004500460045004c002d0049005000430001"
                        "0014004b0049004500460045004c002d0049005000430004"
                        "0014004b0049004500460045004c002d0049005000430003"
                        "0014004b0049004500460045004c002d0049005000430006"
                        "000400010000000000000000570069006e0064006f007700"
                        "7300200035002e0031000000570069006e0064006f007700"
                        "73002000320030003000300020004c0041004e0020004d00"
                        "61006e00610067006500720000");


        let buffer = BytesMut::from(&blob[..]).freeze();

        let reply = parse::<SessionSetup>(buffer).expect("can't parse SMB blob");

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
