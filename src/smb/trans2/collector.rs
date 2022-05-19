use std::collections::HashMap;

use bytes::{Bytes, BytesMut, BufMut};
use itertools::Itertools;

use crate::smb::Error;
use super::reply::Transact2;
use super::SubReply;


/// Collects parameter and data for a Transact2 subcommand.
pub(crate) struct CollectTrans2 {
    parameter: Collector,
    data: Collector,
}

impl CollectTrans2 {
    pub(crate) fn new() -> Self {
        Self {
            parameter: Collector::new(),
            data: Collector::new(),
        }
    }

    /// adds the given Transact2 msg to the collection. returns true, if
    /// the collection is done.
    pub(crate) fn add(&mut self, msg: Transact2) -> Result<bool, Error> {
        self.parameter.add(msg.parameter, msg.parameter_offset, msg.parameter_total)?;
        self.data.add(msg.data, msg.data_offset, msg.data_total)?;

        Ok(self.parameter.is_ready() && self.data.is_ready())
    }

    /// reassembles and parses the subreply
    pub(crate) fn get_subreply<R: SubReply>(self) -> Result<R, Error> {
        let parameter = self.parameter.get()?;
        let data = self.data.get()?;
        let subreply = R::parse(parameter, data)?;
        Ok(subreply)
    }
}


struct Collector {
    fragments: HashMap<usize, Bytes>,
    total: Option<usize>,
}

impl Collector {
    fn new() -> Self {
        Self {
            fragments: HashMap::new(),
            total: None,
        }
    }

    fn add(&mut self, data: Bytes, offset: usize, total: usize)
        -> Result<(), Error>
    {
        if let Some(saved_total) = self.total {
            // safety check: if server changes it's mind about total buffer
            // size, we bail!
            if saved_total != total {
                return Err(Error::Reassemble(format!("server changed it's mind about total packet size: {} vs {}", saved_total, total)));
            }
        } else {
            self.total = Some(total);
        }

        // don't do anything, if there is no data given
        if data.len() == 0 {
            return Ok(());
        }

        // add data to our fragment buffer
        if let Some(_) = self.fragments.insert(offset, data) {
            return Err(Error::Reassemble(format!("got fragment at offset {} twice", offset)));
        }

        Ok(())
    }

    fn len(&self) -> usize {
        self.fragments.iter().map(|(_,b)| b.len()).sum()
    }

    fn is_ready(&self) -> bool {
        if let Some(total) = self.total {
            self.len() >= total
        } else {
            false
        }
    }

    fn get(mut self) -> Result<Bytes, Error> {
        let total = self.total.ok_or(Error::InvalidData)?;

        if self.len() != total {
            return Err(Error::Reassemble(format!("length does not match, want {}, but got {}", total, self.len())));
        }

        let mut buffer = BytesMut::with_capacity(total);

        for (offset, data) in self.fragments.iter_mut().sorted() {
            if buffer.len() != *offset {
                return Err(Error::Reassemble(format!("offset mismatch, got: {}, expected: {}", *offset, buffer.len())));
            }

            buffer.put(data);
        }

        Ok(buffer.freeze())
    }
}
