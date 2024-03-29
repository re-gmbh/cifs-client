use bytes::{Bytes, BytesMut, BufMut};

use crate::utils;
use crate::win::*;

use super::Error;
use super::common::*;
use super::info::*;
use super::reply::Handle;
use super::trans;


pub(crate) trait Msg {
    const CMD: Cmd;
    const ANDX: bool;

    /// Generate body for this SMB message based on given header info. This
    /// is not intended to be called directly. Use write method below.
    fn body(&self, _info: &Info, _parameter: &mut BytesMut, _data: &mut BytesMut)
        -> Result<(), Error>
    {
        Ok(())
    }

    /// Fix header with information specific to this message.
    fn fix_header(&self, _info: &mut Info) {
    }

    /// Add binary representation of this message to given buffer. The SMB
    /// header info is assumed to be already written and given here for
    /// information only.
    fn write(&self, info: &Info, buffer: &mut BytesMut) -> Result<(), Error> {
        // create space for packet parameter and data
        let mut parameter = BytesMut::with_capacity(2*255);
        let mut data = BytesMut::with_capacity(SMB_MAX_LEN);

        // we don't use AndX in our messages for now
        if Self::ANDX {
            AndX {
                cmd: Cmd::NoCommand,
                offset: 0,
            }.write(&mut parameter);
        }

        self.body(&info, &mut parameter, &mut data)?;


        // write packet parameter
        let parameter_len: u8 = (parameter.len() / 2)
            .try_into()
            .map_err(|_| Error::CreatePacket("parameter length too big".to_owned()))?;

        if parameter.len() > buffer.remaining_mut() {
            return Err(Error::CreatePacket("packet buffer too small for parameter".to_owned()));
        }

        buffer.put_u8(parameter_len);
        buffer.put(parameter);

        // write packet data
        let data_len: u16 = data
            .len()
            .try_into()
            .map_err(|_| Error::CreatePacket("data length too big".to_owned()))?;

        if data.len() > buffer.remaining_mut() {
            return Err(Error::CreatePacket("packet buffer too small for data".to_owned()));
        }

        buffer.put_u16_le(data_len);
        buffer.put(data);

        Ok(())
    }
}


/// This empty struct represents the SMB_COM_NEGOTIATE message, which
/// is the first message send to a CIFS server
pub struct Negotiate {}

impl Msg for Negotiate {
    const CMD: Cmd = Cmd::Negotiate;
    const ANDX: bool = false;

    fn body(&self, _info: &Info, _parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        for dialect in SMB_SUPPORTED_DIALECTS {
            data.put_u8(0x02);
            data.put(dialect.as_bytes());
            data.put_u8(0x00);
        }

        Ok(())
    }
}


/// Parameter for SMB_COM_SESSION_SETUP_ANDX, which is send right after negotiation
/// and used for authorization as well as sending client setup data back to server
pub struct SessionSetup {
    pub max_buffer_size: u16,
    pub max_mpx_count: u16,
    pub vc_number: u16,
    pub session_key: u32,
    pub capabilities: Capabilities,
    mode: SessionSetupMode,
}

enum SessionSetupMode {
    Classic {
        user: String,
        domain: String,
        secret: [u8; 24],
    },

    Extended { blob: Bytes },
}

impl SessionSetup {
    pub fn with_auth(user: String, domain: String, secret: [u8; 24]) -> Self {
        let mode = SessionSetupMode::Classic { user, domain, secret };

        let caps = Capabilities::UNICODE
                 | Capabilities::LARGE_FILES
                 | Capabilities::NT_SMBS
                 | Capabilities::NTSTATUS;


        SessionSetup {
            max_buffer_size: 65535,
            max_mpx_count: 0,
            vc_number: 0,
            session_key: 0,
            capabilities: caps,
            mode,
        }
    }
    pub fn with_blob(blob: Bytes) -> Self {
        let mode = SessionSetupMode::Extended { blob };

        let caps = Capabilities::UNICODE
                 | Capabilities::LARGE_FILES
                 | Capabilities::NT_SMBS
                 | Capabilities::NTSTATUS
                 | Capabilities::EXTENDED_SECURITY;


        SessionSetup {
            max_buffer_size: 65535,
            max_mpx_count: 0,
            vc_number: 0,
            session_key: 0,
            capabilities: caps,
            mode,
        }
    }
}

impl Msg for SessionSetup {
    const CMD: Cmd = Cmd::SessionSetup;
    const ANDX: bool = true;

    fn body(&self, info: &Info, parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        // parameter
        parameter.put_u16_le(self.max_buffer_size);
        parameter.put_u16_le(self.max_mpx_count);
        parameter.put_u16_le(self.vc_number);
        parameter.put_u32_le(self.session_key);

        match &self.mode {
            SessionSetupMode::Classic { secret, .. } => {
                let secret_len: u16 = secret
                    .len()
                    .try_into()
                    .map_err(|_| Error::CreatePacket("secret in SessionSetup too big".to_owned()))?;

                parameter.put_u16_le(secret_len);
                parameter.put_u16_le(secret_len);
            }

            SessionSetupMode::Extended { blob } => {
                let blob_len: u16 = blob
                    .len()
                    .try_into()
                    .map_err(|_| Error::CreatePacket("blob in SessionSetup too big".to_owned()))?;

                parameter.put_u16_le(blob_len);
            }
        }

        parameter.put_u32_le(0);        // reserved
        parameter.put_u32_le(self.capabilities.bits());

        // data
        match &self.mode {
            SessionSetupMode::Classic { user, domain, secret } => {
                data.put(secret.as_ref());
                data.put(secret.as_ref());
                // 16bit alignment padding
                if data.len() % 2 == 0 {
                    data.put_u8(0);
                }
                data.put(utils::encode_utf16le_0(user).as_ref());
                data.put(utils::encode_utf16le_0(domain).as_ref());
            }

            SessionSetupMode::Extended { blob } => {
                data.put(blob.as_ref());
                // 16bit alignment pad for unicode
                if blob.len() % 2 == 0 {
                    data.put_u8(0);
                }
            }
        }

        if info.flags2.contains(Flags2::UNICODE) {
            data.put_u16_le(0); // os_name: just zero-terminatation
            data.put_u16_le(0); // lanman: just zero-terminatation
        } else {
            data.put_bytes(0, 2);
        }

        Ok(())
    }
}




/// Parameter for SMB_COM_TREE_CONNECT_ANDX, which is used to 'mount' a share
pub struct TreeConnect {
    path: String,
    password: String,
    flags: TreeConnectFlags,
}

impl TreeConnect {
    pub fn new(path: String, password: String) -> Self {
        let flags = TreeConnectFlags::EXTENDED_RESPONSE;

        TreeConnect {
            path,
            password,
            flags,
        }
    }
}

impl Msg for TreeConnect {
    const CMD: Cmd = Cmd::TreeConnect;
    const ANDX: bool = true;

    fn body(&self, info: &Info, parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        // normalize password: if none is given replace it with a single binary zero
        let password = if self.password.len() > 0 {
            self.password.as_bytes()
        } else {
            &b"\x00"[..]
        };

        let password_length: u16 = password
            .len()
            .try_into()
            .map_err(|_| Error::CreatePacket("password too long".to_owned()))?;

        // parameter
        parameter.put_u16_le(self.flags.bits());
        parameter.put_u16_le(password_length);

        // data
        data.put(password);

        if info.flags2.contains(Flags2::UNICODE) {
            // 16bith alignment padding
            if password.len() % 2 == 0 {
                data.put_u8(0);
            }

            data.put(utils::encode_utf16le(&self.path).as_ref());
            data.put_u16_le(0);
        } else {
            data.put(self.path.as_bytes());
            data.put_u8(0);
        }

        // zero-terminated name of service ('?????' matches anything)
        data.put_bytes(0x3f, 5);
        data.put_u8(0);

        Ok(())
    }
}


/// Parameter for COM_TREE_DISCONNECT message
pub struct TreeDisconnect {
    tid: u16,
}

impl TreeDisconnect {
    pub fn new(tid: u16) -> Self {
        Self {
            tid,
        }
    }
}

impl Msg for TreeDisconnect {
    const CMD: Cmd = Cmd::TreeDisconnect;
    const ANDX: bool = false;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }
}


/// Open defines the parameter for the SMB_COM_NT_CREATE_ANDX message,
/// which is used to open a new or existing file.
pub struct Open {
    tid: u16,
    filename: String,
    create_flags: CreateFlags,
    directory: u32,
    access: FileAccessMask,
    allocation_size: u64,
    attributes: ExtFileAttr,
    share_access: ShareAccess,
    disposition: CreateDisposition,
    options: CreateOptions,
    impersonation: ImpersonationLevel,
    security: SecurityFlags,
}

impl Open {
    pub fn file_ro(tid: u16, filename: String) -> Self {
        Self {
            tid,
            filename,
            create_flags: CreateFlags::empty(),
            directory: 0,
            access: FileAccessMask::READ | FileAccessMask::READ_EA | FileAccessMask::SYNCHRONIZE,
            allocation_size: 0,
            attributes: ExtFileAttr::empty(),
            share_access: ShareAccess::READ,
            disposition: CreateDisposition::OPEN,
            options: CreateOptions::NON_DIRECTORY,
            impersonation: ImpersonationLevel::IMPERSONATE,
            security: SecurityFlags::empty(),
        }
    }

    pub fn dir(tid: u16, filename: String) -> Self {
        Self {
            tid,
            filename,
            create_flags: CreateFlags::empty(),
            directory: 0,
            access: FileAccessMask::READ,
            allocation_size: 0,
            attributes: ExtFileAttr::empty(),
            share_access: ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
            disposition: CreateDisposition::OPEN,
            options: CreateOptions::DIRECTORY,
            impersonation: ImpersonationLevel::IMPERSONATE,
            security: SecurityFlags::empty(),
        }
    }
}

impl Msg for Open {
    const CMD: Cmd = Cmd::Create;
    const ANDX: bool = true;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }

    fn body(&self, _info: &Info, parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        let encoded_filename = utils::encode_utf16le_0(&self.filename);
        let filename_length: u16 = encoded_filename
            .len()
            .try_into()
            .map_err(|_| Error::CreatePacket("filename too long".to_owned()))?;

        // parameter
        parameter.put_u8(0);    // reserved
        parameter.put_u16_le(filename_length);
        parameter.put_u32_le(self.create_flags.bits());
        parameter.put_u32_le(self.directory);
        parameter.put_u32_le(self.access.bits());
        parameter.put_u64_le(self.allocation_size);
        parameter.put_u32_le(self.attributes.bits());
        parameter.put_u32_le(self.share_access.bits());
        parameter.put_u32_le(self.disposition.bits());
        parameter.put_u32_le(self.options.bits());
        parameter.put_u32_le(self.impersonation.bits());
        parameter.put_u8(self.security.bits());

        // data
        data.put_u8(0); // alignment padding
        data.put(encoded_filename.as_ref());

        Ok(())
    }
}


/// Parameter for the SMB_COM_CLOSE message
pub struct Close {
    tid: u16,
    fid: u16,
}

impl Close {
    pub fn new(tid: u16, fid: u16) -> Self {
        Close {
            tid,
            fid,
        }
    }

    pub fn handle(file: &Handle) -> Self {
        Self::new(file.tid, file.fid)
    }
}

impl Msg for Close {
    const CMD: Cmd = Cmd::Close;
    const ANDX: bool = false;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }

    fn body(&self, _info: &Info, parameter: &mut BytesMut, _data: &mut BytesMut)
        -> Result<(), Error>
    {
        parameter.put_u16_le(self.fid);
        // last time modified (0 means don't update)
        parameter.put_u32_le(0);

        Ok(())
    }
}


/// Parameter for the SMB_COM_READ_ANDX (0x2e) message
pub struct Read {
    tid: u16,
    fid: u16,
    offset: u64,
}

impl Read {
    pub fn new(tid: u16, fid: u16, offset: u64) -> Self {
        Self {
            tid,
            fid,
            offset,
        }
    }

    pub fn handle(file: &Handle, offset: u64) -> Self {
        Self::new(file.tid, file.fid, offset)
    }
}

impl Msg for Read {
    const CMD: Cmd = Cmd::Read;
    const ANDX: bool = true;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }

    fn body(&self, _info: &Info, parameter: &mut BytesMut, _data: &mut BytesMut)
        -> Result<(), Error>
    {
        // parameter
        parameter.put_u16_le(self.fid);
        parameter.put_u32_le((self.offset & 0xffffffff) as u32);
        parameter.put_u16_le(SMB_READ_MAX);
        parameter.put_u16_le(SMB_READ_MIN);

        // the following is either higher bytes of max_count (file)
        // or a timeout in ms (pipe)
        parameter.put_u32_le(0);

        // 'remaining' bytes (ignored by modern dialects)
        parameter.put_u16_le(0);

        parameter.put_u32_le((self.offset >> 32) as u32);

        Ok(())
    }
}



/// Parameter for SMB_COM_DELETE (0x06), see 2.2.4.7 in CIFS
pub struct Delete {
    tid: u16,
    filename: String,
    search: FileAttr,
}

impl Delete {
    pub fn file(tid: u16, filename: String) -> Self {
        Self {
            tid,
            filename,
            search: FileAttr::HIDDEN | FileAttr::SYSTEM,
        }
    }
}

impl Msg for Delete {
    const CMD: Cmd = Cmd::Delete;
    const ANDX: bool = false;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }

    fn body(&self, _info: &Info, parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        parameter.put_u16_le(self.search.bits());

        data.put_u8(0x04);      // MUST be 0x04 according to spec
        data.put(utils::encode_utf16le_0(&self.filename).as_ref());

        Ok(())
    }
}

/// Parameter for SMB_COM_DELETE_DIRECTORY (0x01), see 2.2.4.2 in CIFS
pub struct Rmdir {
    tid: u16,
    dirname: String,
}

impl Rmdir {
    pub fn new(tid: u16, dirname: String) -> Self {
        Self { tid, dirname }
    }
}

impl Msg for Rmdir {
    const CMD: Cmd = Cmd::Rmdir;
    const ANDX: bool = false;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }

    fn body(&self, _info: &Info, _parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        data.put_u8(0x04);      // MUST be 0x04 according to spec
        data.put(utils::encode_utf16le_0(&self.dirname).as_ref());

        Ok(())
    }
}


/// Parameter for SMB_COM_NT_TRANSACT
pub(crate) struct Transact<T> {
    tid: u16,
    subcmd: T,
}

impl<T: trans::SubCmd> Transact<T> {
    pub(crate) fn new(tid: u16, subcmd: T) -> Self {
        Self {
            tid,
            subcmd,
        }
    }
}

impl<T: trans::SubCmd> Msg for Transact<T> {
    const CMD: Cmd = Cmd::Transact;
    const ANDX: bool = false;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }

    fn body(&self, _info: &Info, parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        // serialize sub command
        let sub_setup = self.subcmd.setup()?;
        let sub_setup_words: u8 = (sub_setup.len() / 2)
            .try_into()
            .map_err(|_| Error::CreatePacket("setup of transaction sub-command is too large".to_owned()))?;

        let sub_parameter = self.subcmd.parameter()?;
        let sub_parameter_len: u32 = sub_parameter.len()
            .try_into()
            .map_err(|_| Error::CreatePacket("parameter of transaction sub-command is too large".to_owned()))?;

        let sub_data = self.subcmd.data()?;
        let sub_data_len: u32 = sub_data.len()
            .try_into()
            .map_err(|_| Error::CreatePacket("data of transaction sub-command is too large".to_owned()))?;

        // position of data relative to SMB header
        let data_start = SMB_HEADER_LEN
                       + 1 + 38 + sub_setup.len()
                       + 2;

        // sub parameter start at the first 32bit-aligned position in data
        let sub_parameter_offset = 4 * ((data_start + 3)/4);
        // sub data start at the next 32bit-aligned position after sub parameter
        let sub_data_offset = 4 * ((sub_parameter_offset + sub_parameter.len() + 3)/4);



        // parameter
        parameter.put_u8(T::MAX_SETUP_COUNT);
        parameter.put_u16_le(0);        // reserved

        // the following are total counts, if mutiple transact messages
        // are used to transfer this sub-command. we only send one message
        // so this is the same as below.
        parameter.put_u32_le(sub_parameter_len);
        parameter.put_u32_le(sub_data_len);

        // max parameter count accepted by client
        parameter.put_u32_le(T::MAX_PARAM_COUNT);

        // max data count accepted by client
        parameter.put_u32_le(T::MAX_DATA_COUNT);

        parameter.put_u32_le(sub_parameter_len);
        parameter.put_u32_le(sub_parameter_offset.try_into().expect("sub_parameter_offset too big"));
        parameter.put_u32_le(sub_data_len);
        parameter.put_u32_le(sub_data_offset.try_into().expect("sub_data_offset too big"));
        parameter.put_u8(sub_setup_words);
        parameter.put_u16_le(T::ID);
        parameter.put(sub_setup);


        // data
        data.put_bytes(0, (4 - (data_start % 4)) % 4);
        data.put(sub_parameter);
        data.put_bytes(0, (4 - (data_start + data.len()) % 4) % 4);
        data.put(sub_data);

        Ok(())
    }

}



#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn create_negotiate() {
        let mut buffer = BytesMut::with_capacity(SMB_MAX_LEN);

        let msg = Negotiate {};
        let info = Info::default(Negotiate::CMD);

        msg.write(&info, &mut buffer)
            .expect("can't create negotiate packet");

        assert_eq!(buffer.as_ref(), hex!("000c00024e54204c4d20302e313200"));
    }


    #[test]
    fn create_session_setup() {

        let blob = Bytes::from(hex!(
            "4e544c4d5353500001000000978208e200000000000000000000000000000000"
            "0a00614a0000000f").as_ref());


        let capabilities = Capabilities::UNICODE
                         | Capabilities::NT_SMBS
                         | Capabilities::NTSTATUS
                         | Capabilities::LEVEL2_OPLOCKS
                         | Capabilities::DYNAMIC_REAUTH
                         | Capabilities::EXTENDED_SECURITY;

        let mode = SessionSetupMode::Extended { blob };

        let msg = SessionSetup {
            max_buffer_size: 4356,
            max_mpx_count: 16,
            vc_number: 0,
            session_key: 0,
            capabilities,
            mode,
        };

        let mut buffer = BytesMut::with_capacity(SMB_MAX_LEN);
        let info = Info::default(SessionSetup::CMD);

        msg.write(&info, &mut buffer)
            .expect("can't create SessionSetup packet");

        assert_eq!(buffer.as_ref(), hex!(
            "0cff00000004111000000000000000280000000000d40000a02d004e544c4d53"
            "53500001000000978208e2000000000000000000000000000000000a00614a00"
            "00000f0000000000"));
    }
}
