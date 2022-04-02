use bytes::{Bytes, BytesMut, BufMut};

use crate::utils;
use crate::win::*;
use super::common::*;
use super::reply::FileHandle;
use super::trans::TransCmd;


pub trait Msg {
    const CMD: RawCmd;
    const ANDX: bool;

    /// generate body for this smb message based on options
    fn body(&self, _opts: &SmbOpts, _parameter: &mut BytesMut, _data: &mut BytesMut) {
    }

    /// generate info data for header of this smb message based on options
    fn info(&self, opts: &SmbOpts) -> Info {
        Info::from_opts(opts)
    }

    /// give binary representation of this message
    fn to_bytes(&self, opts: &SmbOpts) -> Result<Bytes, Error> {
        let mut buffer = BytesMut::with_capacity(opts.max_smb_size);

        // create info for this packet
        let info = self.info(opts);

        // write header
        buffer.put(&SMB_MAGIC[..]);
        buffer.put_u8(Self::CMD as u8);
        info.write(&mut buffer);

        // create space for package parameter and data
        let mut parameter = BytesMut::with_capacity(2*255);
        let mut data = BytesMut::with_capacity(SMB_MAX_LEN);

        // we don't use AndX in our messages for now
        if Self::ANDX {
            AndX {
                cmd: RawCmd::NoCommand,
                offset: 0,
            }.write(&mut parameter);
        }

        self.body(opts, &mut parameter, &mut data);


        // write package parameter
        let parameter_len: u8 = (parameter.len() / 2)
            .try_into()
            .map_err(|_| Error::CreatePackage("parameter length too big".to_owned()))?;

        if parameter.len() > buffer.remaining_mut() {
            return Err(Error::CreatePackage("package buffer too small for parameter".to_owned()));
        }

        buffer.put_u8(parameter_len);
        buffer.put(parameter);

        // write package data
        let data_len: u16 = data
            .len()
            .try_into()
            .map_err(|_| Error::CreatePackage("data length too big".to_owned()))?;

        if data.len() > buffer.remaining_mut() {
            return Err(Error::CreatePackage("package buffer too small for data".to_owned()));
        }

        buffer.put_u16_le(data_len);
        buffer.put(data);

        Ok(buffer.freeze())
    }
}


/// This empty struct represents the SMB_COM_NEGOTIATE message, which
/// is the first message send to a CIFS server
pub struct Negotiate {}

impl Msg for Negotiate {
    const CMD: RawCmd = RawCmd::Negotiate;
    const ANDX: bool = false;

    fn body(&self, _opts: &SmbOpts, _parameter: &mut BytesMut, data: &mut BytesMut) {
        for dialect in SMB_SUPPORTED_DIALECTS {
            data.put_u8(0x02);
            data.put(dialect.as_bytes());
            data.put_u8(0x00);
        }
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
    pub security_blob: Bytes,
}

impl SessionSetup {
    pub fn new(auth_blob: Bytes) -> Self {
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
            security_blob: auth_blob,
        }
    }
}

impl Msg for SessionSetup {
    const CMD: RawCmd = RawCmd::SessionSetup;
    const ANDX: bool = true;

    fn body(&self, opts: &SmbOpts, parameter: &mut BytesMut, data: &mut BytesMut) {
        // safety
        let blob_len: u16 = self.security_blob
                                .len()
                                .try_into()
                                .expect("security_blob in SessionSetup is to big");
        // parameter
        parameter.put_u16_le(self.max_buffer_size);
        parameter.put_u16_le(self.max_mpx_count);
        parameter.put_u16_le(self.vc_number);
        parameter.put_u32_le(self.session_key);
        parameter.put_u16_le(blob_len);
        parameter.put_u32_le(0);
        parameter.put_u32_le(self.capabilities.bits());

        // data
        data.put(self.security_blob.as_ref());

        if opts.unicode {
            // 16bit alignment pad for unicode
            if self.security_blob.len() % 2 == 0 {
                data.put_u8(0);
            }
            data.put_u16_le(0); // os_name: just zero-terminatation
            data.put_u16_le(0); // lanman: just zero-terminatation
        } else {
            data.put_bytes(0, 2);
        }
    }
}




/// Parameter for SMB_COM_TREE_CONNECT_ANDX, which is used to 'mount' a share
pub struct TreeConnect {
    path: String,
    password: String,
    flags: TreeConnectFlags,
}

impl TreeConnect {
    pub fn new(path: &str, password: &str) -> Self {
        let flags = TreeConnectFlags::EXTENDED_RESPONSE;

        TreeConnect {
            path: path.to_owned(),
            password: password.to_owned(),
            flags,
        }
    }
}

impl Msg for TreeConnect {
    const CMD: RawCmd = RawCmd::TreeConnect;
    const ANDX: bool = true;

    fn body(&self, opts: &SmbOpts, parameter: &mut BytesMut, data: &mut BytesMut) {
        // normalize password: if none is given replace it with a single binary zero
        let password = if self.password.len() > 0 {
            self.password.as_bytes()
        } else {
            &b"\x00"[..]
        };

        let password_length: u16 = password.len()
                                           .try_into()
                                           .expect("password too long");

        // parameter
        parameter.put_u16_le(self.flags.bits());
        parameter.put_u16_le(password_length);

        // data
        data.put(password);

        if opts.unicode {
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
    const CMD: RawCmd = RawCmd::TreeDisconnect;
    const ANDX: bool = false;

    fn info(&self, opts: &SmbOpts) -> Info {
        let mut info = Info::from_opts(opts);
        info.tid = self.tid;
        info
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
            create_flags: CreateFlags::REQUEST_OPLOCK | CreateFlags::REQUEST_OPBATCH,
            directory: 0,
            access: FileAccessMask::READ | FileAccessMask::READ_EA,
            allocation_size: 0,
            attributes: ExtFileAttr::empty(),
            share_access: ShareAccess::READ,
            disposition: CreateDisposition::OPEN,
            options: CreateOptions::NON_DIRECTORY | CreateOptions::SEQUENTIAL_ONLY,
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
    const CMD: RawCmd = RawCmd::Create;
    const ANDX: bool = true;

    /// generate info data for header of this smb message based on options
    fn info(&self, opts: &SmbOpts) -> Info {
        let mut info = Info::from_opts(opts);
        info.tid = self.tid;

        info
    }

    fn body(&self, _opts: &SmbOpts, parameter: &mut BytesMut, data: &mut BytesMut) {
        let filename_length: u16 = self.filename.len().try_into().expect("filename too long");

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
        data.put(utils::encode_utf16le_0(&self.filename).as_ref());
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

    pub fn handle(file: FileHandle) -> Self {
        Self::new(file.tid, file.fid)
    }
}

impl Msg for Close {
    const CMD: RawCmd = RawCmd::Close;
    const ANDX: bool = false;

    fn info(&self, opts: &SmbOpts) -> Info {
        let mut info = Info::from_opts(opts);
        info.tid = self.tid;
        info
    }

    fn body(&self, _opts: &SmbOpts, parameter: &mut BytesMut, _data: &mut BytesMut) {
        parameter.put_u16_le(self.fid);
        // last time modified (0 means don't update)
        parameter.put_u32_le(0);
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

    pub fn handle(file: &FileHandle, offset: u64) -> Self {
        Self::new(file.tid, file.fid, offset)
    }
}

impl Msg for Read {
    const CMD: RawCmd = RawCmd::Read;
    const ANDX: bool = true;

    fn info(&self, opts: &SmbOpts) -> Info {
        let mut info = Info::from_opts(opts);
        info.tid = self.tid;
        info
    }

    fn body(&self, _opts: &SmbOpts, parameter: &mut BytesMut, _data: &mut BytesMut) {
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
    }
}


/// Parameter for SMB_COM_NT_TRANSACT with
pub(crate) struct Transact<T> {
    tid: u16,
    subcmd: T,
}

impl<T: TransCmd> Transact<T> {
    pub(crate) fn new(tid: u16, subcmd: T) -> Self {
        Self {
            tid,
            subcmd,
        }
    }
}

impl<T: TransCmd> Msg for Transact<T> {
    const CMD: RawCmd = RawCmd::Transact;
    const ANDX: bool = false;

    fn info(&self, opts: &SmbOpts) -> Info {
        let mut info = Info::from_opts(opts);
        info.tid = self.tid;
        info
    }

    fn body(&self, _opts: &SmbOpts, parameter: &mut BytesMut, data: &mut BytesMut) {
        // serialize sub command
        let sub_setup = self.subcmd.setup();
        let sub_setup_words: u8 = (sub_setup.len() / 2)
            .try_into()
            .expect("setup of transaction sub-command is too large");

        let sub_parameter = self.subcmd.parameter();
        let sub_parameter_len: u32 = sub_parameter.len()
            .try_into()
            .expect("parameter of transaction sub-command is too large");

        let sub_data = self.subcmd.data();
        let sub_data_len: u32 = sub_data.len()
            .try_into()
            .expect("data of transaction sub-command is too large");

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
    }

}


#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn create_negotiate() {
        let msg = Negotiate {};
        let package = msg.to_bytes(&SmbOpts::default())
            .expect("can't create negotiate package");

        assert_eq!(&package[..], hex!(
            "ff534d4272000000001843c8000000000000000000000000fffffffe00000000"
            "000c00024e54204c4d20302e313200"));
    }


    #[test]
    fn create_session_setup() {
        let security_blob = Bytes::from(hex!(
            "4e544c4d5353500001000000978208e200000000000000000000000000000000"
            "0a00614a0000000f").as_ref());

        let msg = SessionSetup {
            max_buffer_size: 4356,
            max_mpx_count: 16,
            vc_number: 0,
            session_key: 0,
            capabilities: Capabilities::default(),
            security_blob: security_blob,
        };

        let opts = SmbOpts::default();
        let package = msg.to_bytes(&opts)
                         .expect("can't create SessionSetup package");

        assert_eq!(&package[..], hex!(
            "ff534d4273000000001843c8000000000000000000000000fffffffe00000000"
            "0cff00000004111000000000000000280000000000d40000a02d004e544c4d53"
            "53500001000000978208e2000000000000000000000000000000000a00614a00"
            "00000f0000000000"));
    }
}
