use bitflags::bitflags;
use bytes::{Bytes, BytesMut, BufMut};

use super::packet::Packet;
use super::*;

bitflags! {
    pub struct Flags: u32 {
        const UNICODE = 0x00000001;
        const OEM = 0x00000002;
        const REQUEST_TARGET = 0x00000004;
        const SIGN = 0x00000010;
        const SEAL = 0x00000020;
        const DATAGRAM = 0x00000040;
        const LMKEY = 0x00000080;
        const NETWARE = 0x00000100;
        const NTLM = 0x00000200;
        const NT_ONLY = 0x00000400;
        const ANONYMOUS = 0x00000800;
        const DOMAIN_SUPPLIED = 0x00001000;
        const WORKSTATION_SUPPLIED = 0x00002000;
        const LOCAL = 0x00004000;
        const ALWAYS_SIGN = 0x00008000;
        const TARGET_TYPE_DOMAIN = 0x00010000;
        const TARGET_TYPE_SERVER = 0x00020000;
        const TARGET_TYPE_SHARE = 0x00040000;
        const NTLM2_KEY = 0x00080000;
        const REQ_INIT_RESP = 0x00100000;
        const REQ_ACCEPT_RESP = 0x00200000;
        const REQ_NONNT_KEY = 0x00400000;
        const TARGET_INFO = 0x00800000;
        const VERSION = 0x02000000;
        const BIT128 = 0x20000000;
        const KEY_EXCHANGE = 0x40000000;
        const BIT56 = 0x80000000;
    }
}

pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
}

impl Version {
    pub fn default() -> Self {
        Version {
            major: 5,
            minor: 0,
            build: 2195,
        }
    }

    fn as_bytes(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(8);
        buffer.put_u8(self.major);
        buffer.put_u8(self.minor);
        buffer.put_u16_le(self.build);
        buffer.put_bytes(0, 3);
        buffer.put_u8(NTLM_REVISION);
        buffer.freeze()
    }
}

struct Origin {
    workstation: String,
    domain: String,
}


pub struct InitMsg {
    flags: Flags,
    origin: Option<Origin>,
    version: Option<Version>,
}

impl InitMsg {
    pub fn new(flags: Flags) -> Self {
        InitMsg {
            flags,
            origin: None,
            version: None,
        }
    }

    pub fn set_origin(&mut self, domain: &str, workstation: &str) {
        let origin = Origin {
            domain: domain.to_owned(),
            workstation: workstation.to_owned(),
        };

        self.origin = Some(origin);
    }

    #[allow(dead_code)]
    pub fn set_version(&mut self, major: u8, minor: u8, build: u16) {
        self.version = Some(Version { major, minor, build });
    }

    pub fn set_default_version(&mut self) {
        self.version = Some(Version::default());
    }


    pub fn to_bytes(&self) -> Result<Bytes, Error> {
        let mut packet = Packet::new();

        packet.append_binary(NTLMSSP_MAGIC);
        packet.append_u32(NTLM_MSG_INIT);
        packet.append_u32(self.flags.bits());

        if let Some(origin) = self.origin.as_ref() {
            packet.append_buffer(origin.domain.as_bytes());
            packet.append_buffer(origin.workstation.as_bytes());
        }
        if let Some(version) = self.version.as_ref() {
            packet.append_binary(version.as_bytes().as_ref());
        }

        packet.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn create_init() {
        /*
         * Generate message type 1 example from
         * http://davenport.sourceforge.net/ntlm.html
         */
        let mut init_msg = InitMsg::new(Flags::UNICODE
                                      | Flags::OEM
                                      | Flags::REQUEST_TARGET
                                      | Flags::NTLM
                                      | Flags::DOMAIN_SUPPLIED
                                      | Flags::WORKSTATION_SUPPLIED);

        init_msg.set_origin("DOMAIN", "WORKSTATION");
        init_msg.set_version(5, 0, 2195);

        let buffer = init_msg
            .to_bytes()
            .expect("error writing NTLM init message");


        /* i swapped positions of domain and workstation data */
        let expected = hex!(
            "4e544c4d53535000010000000732000006000600280000000b000b002e000000"
            "050093080000000f444f4d41494e574f524b53544154494f4e");

        assert_eq!(&buffer[..], expected);
    }
}
