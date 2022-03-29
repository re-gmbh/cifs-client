/// Hacky implementation of the NTLM Authentication Protocol and Security
/// Support Provider.

mod error;
mod buffer;
mod packet;
mod auth;

use bitflags::bitflags;
use bytes::{Bytes, Buf, BytesMut, BufMut};

pub use error::Error;
pub use auth::Auth;
use packet::Packet;
use buffer::Buffer;


const NTLMSSP_MAGIC: &[u8] = b"NTLMSSP\0";
const NTLM_MSG_INIT: u32 = 1;
const NTLM_MSG_CHALLENGE: u32 = 2;
const NTLM_MSG_RESPONSE: u32 = 3;
const NTLM_REVISION: u8 = 15;


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

struct Version {
    major: u8,
    minor: u8,
    build: u16,
}

impl Version {
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


#[derive(Debug)]
pub struct Challenge {
    pub target: String,
    pub flags: Flags,
    pub challenge: Bytes,
    pub info: Bytes,
}


impl Challenge {
    pub fn parse(msg: &Bytes) -> Result<Self, Error> {
        let mut parse = msg.clone();

        // check magic
        let magic = parse.copy_to_bytes(NTLMSSP_MAGIC.len());
        if &magic[..] != NTLMSSP_MAGIC {
            return Err(Error::InvalidPacket);
        }

        // check msg type
        let msgtype = parse.get_u32_le();
        if msgtype != NTLM_MSG_CHALLENGE {
            return Err(Error::InvalidPacket);
        }

        let target_buffer = Buffer::parse(&mut parse)?;
        let flags = Flags::from_bits_truncate(parse.get_u32_le());

        // extract 8 bytes challenge (this is what we are really after)
        let challenge = parse.copy_to_bytes(8);

        // 8 bytes context, we ignore this
        parse.advance(8);

        let info_buffer = Buffer::parse(&mut parse)?;

        // now extract buffers
        let target = target_buffer.extract_string(msg, flags.contains(Flags::UNICODE))?;
        let info = info_buffer.extract(msg);

        Ok(Challenge { target, flags, challenge, info })
    }
}


pub struct NTLM {
    flags: Flags,
    auth: Option<Auth>,
    workstation: Option<String>,
    version: Option<Version>,
    challenge: Option<Challenge>,
}

impl NTLM {
    pub fn new() -> Self {
        NTLM {
            flags: Flags::empty(),
            auth: None,
            workstation: None,
            version: None,
            challenge: None,
        }
    }

    pub fn set_flags(&mut self, flags: Flags) {
        self.flags = flags;
    }

    pub fn set_auth(&mut self, user: &str, domain: &str, pass: &str) {
        self.auth = Some(Auth::new(user, domain, pass));
    }

    pub fn set_workstation(&mut self, workstation: &str) {
        self.workstation = Some(workstation.to_owned());
    }

    pub fn set_version(&mut self, major: u8, minor: u8, build: u16) {
        self.version = Some(Version { major, minor, build });
    }

    pub fn create_initialize_msg(&self, out: &mut BytesMut) -> Result<(), Error> {
        let mut packet = Packet::new();

        packet.append_binary(NTLMSSP_MAGIC);
        packet.append_u32(NTLM_MSG_INIT);
        packet.append_u32(self.flags.bits());

        if let Some(auth) = self.auth.as_ref() {
            packet.append_buffer(auth.domain.as_bytes());
        }
        if let Some(workstation) = self.workstation.as_ref() {
            packet.append_buffer(workstation.as_bytes());
        }
        if let Some(version) = self.version.as_ref() {
            packet.append_binary(version.as_bytes().as_ref());
        }

        packet.write(out)
    }


    pub fn parse_challenge_msg(&mut self, msg: &Bytes) -> Result<(), Error> {
        self.challenge = Some(Challenge::parse(msg)?);
        Ok(())
    }


    pub fn create_authenticate_msg(&self, out: &mut BytesMut) -> Result<(), Error> {
        let challenge = self.challenge
                            .as_ref()
                            .ok_or(Error::NeedChallenge)?;

        let auth = self.auth
                       .as_ref()
                       .ok_or(Error::NeedAuth)?;

        let workstation = self.workstation
                              .as_ref()
                              .ok_or(Error::NeedWorkstation)?;

        let (_sk, response) = auth.response(challenge)?;

        let mut packet = Packet::new();
        packet.append_binary(NTLMSSP_MAGIC);
        packet.append_u32(NTLM_MSG_RESPONSE);
        packet.append_buffer(&[0u8; 24]);                   // Empty LM Response
        packet.append_buffer(&response);                    // NTLMv2 Response
        packet.append_buffer(auth.domain.as_bytes());
        packet.append_buffer(auth.user.as_bytes());
        packet.append_buffer(workstation.as_bytes());

        // optional stuff
        //packet.append_buffer(&sk);
        //packet.append_u32(self.flags.bits());
        //if let Some(version) = self.version.as_ref() {
        //    packet.append_binary(version.as_bytes().as_ref());
        //}

        packet.write(out)
    }
}


#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use hex_literal::hex;
    use super::*;

    #[test]
    fn create_init() {
        /*
         * Generate message type 1 example from
         * http://davenport.sourceforge.net/ntlm.html
         */
        let mut ntlm = NTLM::new();

        ntlm.set_flags(Flags::UNICODE
                     | Flags::OEM
                     | Flags::REQUEST_TARGET
                     | Flags::NTLM
                     | Flags::DOMAIN_SUPPLIED
                     | Flags::WORKSTATION_SUPPLIED
        );

        ntlm.set_auth("user", "DOMAIN", "SecREt01");
        ntlm.set_workstation("WORKSTATION");
        ntlm.set_version(5, 0, 2195);

        let mut buffer = BytesMut::with_capacity(512);
        ntlm.create_initialize_msg(&mut buffer)
            .expect("error writing NTLM init message");

        /* i swapped positions of domain and workstation data */
        let expected = hex!("4e544c4d53535000010000000732000006000600280000000b000b002e000000"
                            "050093080000000f444f4d41494e574f524b53544154494f4e");

        assert_eq!(&buffer[..], expected);
    }


    #[test]
    fn parse_challenge() {
        let msg_challenge = Bytes::from(hex!(
                "4e544c4d53535000020000000c000c003000000001028100"
                "0123456789abcdef0000000000000000620062003c000000"
                "44004f004d00410049004e0002000c0044004f004d004100"
                "49004e0001000c0053004500520056004500520004001400"
                "64006f006d00610069006e002e0063006f006d0003002200"
                "7300650072007600650072002e0064006f006d0061006900"
                "6e002e0063006f006d0000000000").as_ref());


        let mut ntlm = NTLM::new();
        ntlm.parse_challenge_msg(&msg_challenge)
            .expect("can't read NTLM challenge");

        let challenge = ntlm.challenge.unwrap();

        assert_eq!(challenge.flags, Flags::UNICODE
                                  | Flags::NTLM
                                  | Flags::TARGET_TYPE_DOMAIN
                                  | Flags::TARGET_INFO);

        assert_eq!(challenge.target, "DOMAIN");
        assert_eq!(&challenge.challenge[..], hex!("0123456789abcdef"));
        assert_eq!(&challenge.info[..], hex!(
                "02000c0044004f004d00410049004e0001000c00530045005200560045005200"
                "0400140064006f006d00610069006e002e0063006f006d000300220073006500"
                "72007600650072002e0064006f006d00610069006e002e0063006f006d000000"
                "0000"));
    }
}
