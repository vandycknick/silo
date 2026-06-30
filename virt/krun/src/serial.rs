use std::fs::File;
use std::io::{self, Read, Write};

#[derive(Debug)]
pub struct SerialConnection {
    read: File,
    write: File,
}

impl SerialConnection {
    pub(crate) fn new(read: File, write: File) -> Self {
        Self { read, write }
    }

    pub fn into_files(self) -> (File, File) {
        (self.read, self.write)
    }
}

impl Read for SerialConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read.read(buf)
    }
}

impl Write for SerialConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write.flush()
    }
}
