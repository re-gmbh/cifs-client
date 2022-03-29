use bytes::{BytesMut, BufMut, Buf};

use super::buffer::Buffer;
use super::Error;

enum PacketEntry {
    Binary(Vec<u8>),
    Buffer(Buffer),
}

impl PacketEntry {
    fn len(&self) -> usize {
        match self {
            PacketEntry::Binary(v) => v.len(),
            PacketEntry::Buffer(_) => 8,
        }
    }
}

pub struct Packet {
    entries: Vec<PacketEntry>,
    extra: Vec<u8>,
}

impl Packet {
    pub fn new() -> Self {
        Packet {
            entries: Vec::new(),
            extra: Vec::new(),
        }
    }

    pub fn append_binary(&mut self, data: &[u8]) {
        self.entries.push(PacketEntry::Binary(Vec::from(data)));
    }

    pub fn append_u32(&mut self, value: u32) {
        self.entries.push(PacketEntry::Binary(Vec::from(value.to_le_bytes())));
    }

    pub fn append_buffer(&mut self, data: &[u8]) {
        let n = data.len();

        let buffer = Buffer {
            length: n,
            capacity: n,
            position: self.extra.len(),
        };

        self.entries.push(PacketEntry::Buffer(buffer));
        self.extra.extend_from_slice(data);
    }

    pub fn write(&self, out: &mut BytesMut) -> Result<(), Error> {
        let offset = self.base_len();

        if out.remaining_mut() < offset + self.extra.len() {
            return Err(Error::InputParameter("NTLM packet too big for output buffer".to_owned()));
        }

        for entry in &self.entries {
            match entry {
                PacketEntry::Binary(data) => out.put(data.as_ref()),
                PacketEntry::Buffer(buffer) => buffer.write(out, offset)?,
            }
        }

        out.put(self.extra.as_ref());
        Ok(())
    }

    fn base_len(&self) -> usize {
        self.entries
            .iter()
            .map(|e| e.len())
            .sum()
    }
}
