use bytes::{Bytes, Buf};

use super::common::*;


#[derive(Debug)]
pub struct ServerSetup {
    pub dialect: &'static str,
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
    pub server_guid: [u8; 16],
}



#[derive(Debug)]
pub enum Reply {
    Negotiate(ServerSetup),

    SessionSetup {
        guest_mode: bool,
        security_blob: Bytes,
    },

}

impl Reply {
    fn parse(cmd: RawCmd, info: &Info, andx: &mut Option<AndX>, buffer: &mut Bytes) -> Result<Self, Error> {
        let parameter_count = buffer.get_u8() as usize;
        let mut parameter = buffer.copy_to_bytes(2*parameter_count);

        let data_count = buffer.get_u16_le() as usize;
        let data = buffer.copy_to_bytes(data_count);

        // first parameter is AndX structure, if this command has one
        if cmd.has_andx() {
            *andx = AndX::parse(&mut parameter)?;
        } else {
            *andx = None;
        }

        match cmd {
            RawCmd::Negotiate => Reply::parse_negotiate(parameter, data),
            RawCmd::SessionSetup => Reply::parse_session_setup(info, parameter, data),

            _ => Err(Error::Unsupported),
        }
    }


    /// parse negotiate reply, this is the version for Flags2::EXTENDED_SECURITY
    fn parse_negotiate(mut parameter: Bytes, mut data: Bytes) -> Result<Self, Error> {
        // strictly there may only be one word, but we only support dialects above
        // NTLM 0.12 and therefor need at least 17 words.
        if parameter.len() < 17 {
            return Err(Error::Unsupported);
        }

        // this must always be here (0xffff means no supported dialects)
        let index = parameter.get_u16_le() as usize;
        if index == 0xffff {
            return Err(Error::InvalidDialect);
        }
        let dialect = SMB_SUPPORTED_DIALECTS.get(index)
                                            .ok_or(Error::InvalidDialect)?;


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

        let mut server_guid = [0u8; 16];
        data.copy_to_slice(&mut server_guid);



        let server_setup = ServerSetup {
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


        Ok(Reply::Negotiate(server_setup))
    }

    fn parse_session_setup(info: &Info, mut parameter: Bytes, mut data: Bytes) -> Result<Self, Error> {
        // parse parameter
        let action = parameter.get_u16_le();
        let blob_length = parameter.get_u16_le() as usize;

        // parse data
        let blob = data.copy_to_bytes(blob_length);

        // these two maybe unicode or ascii depending on flags2
        //let os_name = read_unicode_str0(&mut data);
        //let lanman = read_unicode_str0(&mut data);

        // build reply
        let reply = Reply::SessionSetup {
            guest_mode: action & 0x0001 == 1,
            security_blob: blob,
        };

        Ok(reply)
    }
}



#[derive(Debug)]
pub struct SMBReply {
    pub info: Info,
    pub replies: Vec<Reply>,
}


impl SMBReply {
    fn parse(buffer: Bytes) -> Result<Self, Error> {
        let mut parse = buffer.clone();

        // check if we have at least our SMB header?
        if parse.remaining() < SMB_HEADER_LEN {
            return Err(Error::InvalidHeader);
        }

        // check magic
        let magic = parse.copy_to_bytes(4);
        if &magic[..] != SMB_MAGIC {
            return Err(Error::InvalidHeader);
        }

        // check command identifier
        let cmd: RawCmd = parse.get_u8().try_into()?;

        // info part of header
        let info = Info::parse(&mut parse)?;

        // this must be a reply
        if !info.flags1.contains(Flags1::REPLY) {
            return Err(Error::ReplyExpected);
        }


        // if extended_security is not set, we have to parse
        // negotiate reply differently... until we support that
        // throw an error
        if !info.flags2.contains(Flags2::EXTENDED_SECURITY) {
            return Err(Error::NeedExtSec);
        }


        //
        // now parse replies
        // 
        let mut replies = Vec::new();
        let mut maybe_andx: Option<AndX> = None;

        let reply = Reply::parse(cmd, &info, &mut maybe_andx, &mut parse)?;
        replies.push(reply);

        while let Some(ref andx) = maybe_andx {
            let mut parse = buffer.slice((andx.offset as usize)..);
            let reply = Reply::parse(andx.cmd, &info, &mut maybe_andx, &mut parse)?;
            replies.push(reply);
        }

        Ok(SMBReply { info, replies })
    }
}


#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use hex_literal::hex;
    use super::*;


    #[test]
    fn parse_negotiate_cmd() {
        let blob = hex!("ff534d4272000000009853c8000000000000000000000000fffffffe00000000"
                        "1100000310000100041100000000010000000000fde300808e6db6b79b3ed801"
                        "0000001000f9fe3c88bf27b444bd3d74f7b2fdbf01");
        let buffer = BytesMut::from(&blob[..]).freeze();
        let smb = SMBReply::parse(buffer).expect("can't parse SMB blob");

        // check header infos
        assert_eq!(smb.info.status, 0);
        assert_eq!(smb.info.flags1, Flags1::REPLY
                                | Flags1::CASE_INSENSITIVE
                                | Flags1::CANONICAL_PATHS);

        assert_eq!(smb.info.flags2, Flags2::UNICODE
                                | Flags2::NTSTATUS
                                | Flags2::EXTENDED_SECURITY
                                | Flags2::LONG_NAMES_USED
                                | Flags2::SIGNATURE_REQUIRED
                                | Flags2::EAS
                                | Flags2::LONG_NAMES_ALLOWED);

        assert_eq!(smb.info.pid, 65279);
        assert_eq!(smb.info.tid, 0xffff);
        assert_eq!(smb.info.uid, 0);
        assert_eq!(smb.info.mid, 0);

        // check reply
        assert_eq!(smb.replies.len(), 1);
        match &smb.replies[0] {
            Reply::Negotiate(setup)  => {
                assert_eq!(setup.dialect, "NT LM 0.12");
                assert_eq!(setup.security_mode, 3);
                assert_eq!(setup.max_mpx_count, 16);
                assert_eq!(setup.max_number_vcs, 1);
                assert_eq!(setup.max_buffer_size, 4356);
                assert_eq!(setup.session_key, 0);
                assert_eq!(setup.capabilities, Capabilities::EXTENDED_SECURITY
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

                assert_eq!(setup.system_time, 0x01d83e9bb7b66d8e);// FIXME implement windows time type
                assert_eq!(setup.timezone, 0);
                assert_eq!(setup.challenge_length, 0);
                assert_eq!(setup.server_guid, hex!("f9fe3c88bf27b444bd3d74f7b2fdbf01"));
            }

            _ => panic!("unexpected reply type"),
        }
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

        let expected_ntlm_blob =
            hex!("4e544c4d5353500002000000140014003800000015828ae2d9102a72"
                 "d8b439d200000000000000006c006c004c0000000501280a0000000f"
                 "4b0049004500460045004c002d00490050004300020014004b004900"
                 "4500460045004c002d00490050004300010014004b00490045004600"
                 "45004c002d00490050004300040014004b0049004500460045004c00"
                 "2d00490050004300030014004b0049004500460045004c002d004900"
                 "50004300060004000100000000000000");

        let buffer = BytesMut::from(&blob[..]).freeze();
        let smb = SMBReply::parse(buffer).expect("can't parse SMB blob");

        assert_eq!(smb.replies.len(), 1);

        match &smb.replies[0] {
            Reply::SessionSetup { guest_mode, security_blob }  => {
                assert_eq!(*guest_mode, false);
                assert_eq!(&security_blob[..], expected_ntlm_blob);
            }

            _ => panic!("expected session setup reply"),
        }
    }
}
