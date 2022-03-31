use bytes::{Bytes, BytesMut, BufMut};

use super::common::*;


pub trait Msg {
    const CMD: RawCmd;
    const ANDX: bool;

    fn write(&self, parameter: &mut BytesMut, data: &mut BytesMut);

    /// create a package of this message with the given information as header
    fn info_package(&self, info: &Info) -> Result<Bytes, Error> {
        let mut buffer = BytesMut::with_capacity(SMB_MAX_LEN);

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

        self.write(&mut parameter, &mut data);


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

    /// package this message with default header
    fn package(&self) -> Result<Bytes, Error> {
        self.info_package(&Info::default())
    }
}


/// Negotiate is the first message send to a CIFS server
pub struct Negotiate {}

impl Msg for Negotiate {
    const CMD: RawCmd = RawCmd::Negotiate;
    const ANDX: bool = false;

    fn write(&self, _parameter: &mut BytesMut, data: &mut BytesMut) {
        for dialect in SMB_SUPPORTED_DIALECTS {
            data.put_u8(0x02);
            data.put(dialect.as_bytes());
            data.put_u8(0x00);
        }
    }
}


/// SessionSetup is send right after negotiation and used for authorization as
/// well as sending client setup data back to server
pub struct SessionSetup {
    pub max_buffer_size: u16,
    pub max_mpx_count: u16,
    pub vc_number: u16,
    pub session_key: u32,
    pub capabilities: Capabilities,
    pub security_blob: Bytes,
    //pub os_name: String,
    //pub lanman: String;
}

impl SessionSetup {
    pub fn new(auth_blob: Bytes) -> Self {
        let caps = Capabilities::UNICODE
                 | Capabilities::LARGE_FILES
                 | Capabilities::NT_SMBS
                 | Capabilities::NTSTATUS
                 | Capabilities::EXTENDED_SECURITY;


        SessionSetup {
            max_buffer_size: 4356,
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

    fn write(&self, parameter: &mut BytesMut, data: &mut BytesMut) {
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
        data.put_u8(0);     // pad
        data.put_u16_le(0); // os_name: just zero-terminatation
        data.put_u16_le(0); // lanman: just zero-terminatation
    }
}





#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn create_negotiate() {
        let msg = Negotiate {};
        let package = msg.package().expect("can't create negotiate package");

        assert_eq!(&package[..], hex!(
            "ff534d4272000000001803c8000000000000000000000000fffffffe00000000"
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

        let package = msg.package()
                         .expect("can't create SessionSetup package");

        assert_eq!(&package[..], hex!(
            "ff534d4273000000001803c8000000000000000000000000fffffffe00000000"
            "0cff00000004111000000000000000280000000000d40000a02d004e544c4d53"
            "53500001000000978208e2000000000000000000000000000000000a00614a00"
            "00000f0000000000"));
    }
}
