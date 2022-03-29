use bytes::{Bytes, Buf, BytesMut, BufMut};

use super::common::*;

#[derive(Debug)]
pub struct SessionSetupData {
    pub max_buffer_size: u16,
    pub max_mpx_count: u16,
    pub vc_number: u16,
    pub session_key: u32,
    pub capabilities: Capabilities,
    pub security_blob: Vec<u8>,
    //pub os_name: String,
    //pub lanman: String;
}


#[derive(Debug)]
pub enum Msg {
    Negotiate,
    SessionSetup(SessionSetupData),
}

impl Msg {
    fn get_raw_cmd(&self) -> RawCmd {
        match self {
            Msg::Negotiate => RawCmd::Negotiate,
            Msg::SessionSetup(_) => RawCmd::SessionSetup,
        }
    }


    pub fn serialize(&self) -> Result<(Bytes,Bytes), Error> {
        let mut parameter = BytesMut::with_capacity(2*255);
        let mut data = BytesMut::with_capacity(SMB_MAX_LEN);

        // we don't use AndX in our messages for now
        if self.get_raw_cmd().has_andx() {
            AndX {
                cmd: RawCmd::NoCommand,
                offset: 0,
            }.write(&mut parameter)?;
        }

        // now serialize message
        match self {
            Msg::Negotiate => {
                // generate dialect list
                for dialect in SMB_SUPPORTED_DIALECTS {
                    data.put_u8(0x02);
                    data.put(dialect.as_bytes());
                    data.put_u8(0x00);
                }

                Ok((parameter.freeze(), data.freeze()))
            }

            Msg::SessionSetup(setup) => {
                // parameter
                parameter.put_u16_le(setup.max_buffer_size);
                parameter.put_u16_le(setup.max_mpx_count);
                parameter.put_u16_le(setup.vc_number);
                parameter.put_u32_le(setup.session_key);
                parameter.put_u16_le(setup.security_blob.len().try_into()?);
                parameter.put_u32_le(0);
                parameter.put_u32_le(setup.capabilities.bits());

                // data
                data.put(&setup.security_blob[..]);
                data.put_u8(0);     // pad
                data.put_u16_le(0); // os_name: just zero-terminatation
                data.put_u16_le(0); // lanman: just zero-terminatation

                Ok((parameter.freeze(), data.freeze()))
            }
        }
    }
}



#[derive(Debug)]
pub struct SMBMsg {
    pub info: Info,
    pub msg: Msg,
}

impl SMBMsg {
    fn write(&self, buffer: &mut BytesMut) -> Result<(), Error> {
        buffer.put(&SMB_MAGIC[..]);
        buffer.put_u8(self.msg.get_raw_cmd() as u8);

        self.info.write(buffer)?;

        let (parameter, data) = self.msg.serialize()?;

        buffer.put_u8((parameter.len() / 2).try_into()?);
        buffer.put(parameter);

        buffer.put_u16_le(data.len().try_into()?);
        buffer.put(data);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn create_negotiate() {
        let smb_msg = SMBMsg {
            info: Info::default(),
            msg: Msg::Negotiate,
        };
        let mut buffer = BytesMut::with_capacity(SMB_MAX_LEN);

        smb_msg.write(&mut buffer)
               .expect("can't serialize SMB negotiate message");

        let expected = hex!(
            "ff534d4272000000001803c8000000000000000000000000fffffffe00000000"
            "000c00024e54204c4d20302e313200");

        assert_eq!(&buffer[..], expected);
    }

    #[test]
    fn create_session_setup() {
        let security_blob = hex!(
            "4e544c4d5353500001000000978208e200000000000000000000000000000000"
            "0a00614a0000000f");

        let setup_data = SessionSetupData {
            max_buffer_size: 4356,
            max_mpx_count: 16,
            vc_number: 0,
            session_key: 0,
            capabilities: Capabilities::default(),
            security_blob: security_blob.to_vec(),
        };

        let smb_msg = SMBMsg {
            info: Info::default(),
            msg: Msg::SessionSetup(setup_data),
        };

        let mut buffer = BytesMut::with_capacity(SMB_MAX_LEN);

        smb_msg.write(&mut buffer)
               .expect("can't serialize SMB session setup");

        let expected = hex!(
            "ff534d4273000000001803c8000000000000000000000000fffffffe00000000"
            "0cff00000004111000000000000000280000000000d40000a02d004e544c4d53"
            "53500001000000978208e2000000000000000000000000000000000a00614a00"
            "00000f0000000000");

        assert_eq!(&buffer[..], expected);
    }
}
