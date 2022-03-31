use bytes::{Bytes, Buf, BytesMut, BufMut};

use crate::utils;
use super::Error;

pub struct Buffer {
    pub length: usize,
    pub capacity: usize,
    pub position: usize,
}

impl Buffer {
    pub fn parse(buffer: &mut Bytes) -> Result<Self, Error> {
        let length = buffer.get_u16_le() as usize;
        let capacity = buffer.get_u16_le() as usize;
        let position = buffer.get_u32_le() as usize;

        let buffer = Buffer { length, capacity, position };

        Ok(buffer)
    }

    pub fn write(&self, buffer: &mut BytesMut, offset: usize) -> Result<(), Error> {
        let position = offset + self.position;

        buffer.put_u16_le(self.length.try_into()?);
        buffer.put_u16_le(self.capacity.try_into()?);
        buffer.put_u32_le(position.try_into()?);
        Ok(())
    }

    pub fn extract(&self, buffer: &Bytes) -> Bytes {
        let a = self.position;
        let b = a + self.length;

        buffer.slice(a..b)
    }

    pub fn extract_string(&self, buffer: &Bytes, unicode: bool) -> Result<String, Error> {
        let raw = self.extract(buffer);

        if unicode {
            utils::parse_utf16le(raw.as_ref())
                .map_err(|_| Error::InvalidPacket)

        } else {
            // just treat as utf8, i know this is not exactly correct since
            // it might use non-ascii characters from DOS codepage.. YOLO!
            String::from_utf8(Vec::from(raw.as_ref()))
                .map_err(|_| Error::InvalidPacket)
        }
    }
}
