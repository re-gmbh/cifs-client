use bytes::{Bytes, Buf};

use super::buffer::Buffer;
use super::packet::Packet;
use super::*;


#[derive(Debug)]
pub struct ChallengeMsg {
    pub target: String,
    pub flags: Flags,
    pub challenge: Bytes,
    pub info: Bytes,
}


impl ChallengeMsg {
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

        // extract 8 bytes challenge (the juicy center we are after)
        let challenge = parse.copy_to_bytes(8);

        // 8 bytes context, we ignore this
        parse.advance(8);

        let info_buffer = Buffer::parse(&mut parse)?;

        // now extract buffers
        let target = target_buffer.extract_string(msg, flags.contains(Flags::UNICODE))?;
        let info = info_buffer.extract(msg);

        Ok(ChallengeMsg { target, flags, challenge, info })
    }

    pub fn response(&self, auth: &Auth) -> Result<Bytes, Error> {
        let (_sk, response) = auth.ntlmv2_authenticate(self)?;

        let mut packet = Packet::new();
        packet.append_binary(NTLMSSP_MAGIC);
        packet.append_u32(NTLM_MSG_RESPONSE);
        packet.append_buffer(&[0u8; 24]);                   // Empty LM Response
        packet.append_buffer(&response);                    // NTLMv2 Response

        let unicode = self.flags.contains(Flags::UNICODE);
        packet.append_string(&auth.domain, unicode);
        packet.append_string(&auth.user, unicode);
        packet.append_string(&auth.workstation, unicode);

        // optional stuff
        //packet.append_buffer(&sk);
        //packet.append_u32(self.flags.bits());
        //if let Some(version) = self.version.as_ref() {
        //    packet.append_binary(version.as_bytes().as_ref());
        //}

        packet.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn parse_challenge() {
        let raw_challenge = Bytes::from(hex!(
                "4e544c4d53535000020000000c000c003000000001028100"
                "0123456789abcdef0000000000000000620062003c000000"
                "44004f004d00410049004e0002000c0044004f004d004100"
                "49004e0001000c0053004500520056004500520004001400"
                "64006f006d00610069006e002e0063006f006d0003002200"
                "7300650072007600650072002e0064006f006d0061006900"
                "6e002e0063006f006d0000000000").as_ref());


        let challenge = ChallengeMsg::parse(&raw_challenge)
            .expect("can't read NTLM challenge");

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
