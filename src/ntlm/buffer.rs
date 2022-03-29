use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::Error;

pub struct Buffer {
    pub length: usize,
    pub capacity: usize,
    pub position: usize,
}

impl Buffer {
    pub fn read(stream: &mut impl io::Read) -> Result<Self, Error> {
        let length = stream.read_u16::<LittleEndian>()? as usize;
        let capacity = stream.read_u16::<LittleEndian>()? as usize;
        let position = stream.read_u32::<LittleEndian>()? as usize;

        let buffer = Buffer { length, capacity, position };

        Ok(buffer)
    }

    pub fn write(&self, stream: &mut impl io::Write, offset: usize) -> Result<(), Error> {
        let position = offset + self.position;

        stream.write_u16::<LittleEndian>(self.length.try_into()?)?;
        stream.write_u16::<LittleEndian>(self.capacity.try_into()?)?;
        stream.write_u32::<LittleEndian>(position.try_into()?)?;
        Ok(())
    }

    pub fn extract<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], Error> {
        let a = self.position;
        let b = a + self.length;

        data.get(a..b)
            .ok_or(Error::InvalidPacket)
    }

    pub fn extract_string(&self, data: &[u8], unicode: bool) -> Result<String, Error> {
        let raw = self.extract(data)?;

        if unicode {
            let n = self.length;
            let iter = (0..n)
                .step_by(2)
                .map(|i| u16::from_le_bytes([raw[i], raw[i+1]]));

            std::char::decode_utf16(iter)
                .collect::<Result<String, std::char::DecodeUtf16Error>>()
                .map_err(|_| Error::InvalidPacket)
        } else {
            // just treat as utf8, i know this is not exactly correct since
            // it might use non-ascii characters from DOS codepage.
            String::from_utf8(Vec::from(raw)).map_err(|_| Error::InvalidPacket)
        }
    }
}
