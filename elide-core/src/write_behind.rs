//! Write-behind for a large sequential file write.
//!
//! A cursor follows the bytes a writer lands in a file. Each time a full
//! window lands, the cursor starts writeback on that window and waits for the
//! writeback of the window before it. The dirty pages behind the write are
//! bounded to two windows, so a concurrent fdatasync on the same disk queues
//! behind two windows of this write at most, and the final `sync_data` finds
//! little left to flush.

use std::fs::File;
use std::io::{self, Write};

/// The window bounds the dirty bytes of one write to twice this size.
pub const WINDOW: u64 = 1 << 20;

/// One writeback action the cursor asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Start writeback on `[start, start + len)`.
    Write { start: u64, len: u64 },
    /// Wait for the writeback of `[start, start + len)` to finish.
    Wait { start: u64, len: u64 },
}

/// The pure part of the write-behind: turns a high-water mark into steps.
#[derive(Debug)]
pub struct Cursor {
    window: u64,
    /// End of the last window whose writeback started.
    issued: u64,
    /// End of the last window whose writeback finished.
    waited: u64,
    /// High-water mark of the bytes the writer landed.
    end: u64,
}

impl Cursor {
    pub fn new(window: u64) -> Self {
        Self {
            window,
            issued: 0,
            waited: 0,
            end: 0,
        }
    }

    /// Records that bytes up to `end` landed and returns the steps due.
    pub fn advance(&mut self, end: u64) -> Vec<Step> {
        self.end = self.end.max(end);
        let mut steps = Vec::new();
        while self.end - self.issued >= self.window {
            let start = self.issued;
            steps.push(Step::Write {
                start,
                len: self.window,
            });
            self.issued = start + self.window;
            if start > self.waited {
                steps.push(Step::Wait {
                    start: self.waited,
                    len: start - self.waited,
                });
                self.waited = start;
            }
        }
        steps
    }
}

/// A file with a write-behind cursor. `written` reports landed bytes for a
/// positional writer; `Write` reports them for a sequential one.
#[derive(Debug)]
pub struct WriteBehindFile {
    file: File,
    cursor: Cursor,
    pos: u64,
}

impl WriteBehindFile {
    pub fn new(file: File) -> Self {
        Self {
            file,
            cursor: Cursor::new(WINDOW),
            pos: 0,
        }
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Reports that the bytes up to `end` landed in the file.
    pub fn written(&mut self, end: u64) -> io::Result<()> {
        for step in self.cursor.advance(end) {
            apply(&self.file, step)?;
        }
        Ok(())
    }
}

impl Write for WriteBehindFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.pos += n as u64;
        self.written(self.pos)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(target_os = "linux")]
fn apply(file: &File, step: Step) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let (start, len, flags) = match step {
        Step::Write { start, len } => (start, len, libc::SYNC_FILE_RANGE_WRITE),
        Step::Wait { start, len } => (
            start,
            len,
            libc::SYNC_FILE_RANGE_WAIT_BEFORE
                | libc::SYNC_FILE_RANGE_WRITE
                | libc::SYNC_FILE_RANGE_WAIT_AFTER,
        ),
    };
    // SAFETY: the fd is open for the life of `file`, and the range and flags
    // are plain integers the kernel validates.
    let rc = unsafe { libc::sync_file_range(file.as_raw_fd(), start as i64, len as i64, flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn apply(_file: &File, _step: Step) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn a_partial_window_asks_for_nothing() {
        let mut c = Cursor::new(8);
        assert_eq!(c.advance(7), vec![]);
    }

    #[test]
    fn the_first_full_window_starts_writeback_and_waits_for_nothing() {
        let mut c = Cursor::new(8);
        assert_eq!(c.advance(8), vec![Step::Write { start: 0, len: 8 }]);
    }

    #[test]
    fn the_second_window_starts_its_writeback_and_waits_for_the_first() {
        let mut c = Cursor::new(8);
        c.advance(8);
        assert_eq!(
            c.advance(16),
            vec![
                Step::Write { start: 8, len: 8 },
                Step::Wait { start: 0, len: 8 }
            ]
        );
    }

    #[test]
    fn a_jump_over_several_windows_issues_each_in_order() {
        let mut c = Cursor::new(8);
        assert_eq!(
            c.advance(25),
            vec![
                Step::Write { start: 0, len: 8 },
                Step::Write { start: 8, len: 8 },
                Step::Wait { start: 0, len: 8 },
                Step::Write { start: 16, len: 8 },
                Step::Wait { start: 8, len: 8 },
            ]
        );
        assert_eq!(c.advance(31), vec![]);
        assert_eq!(
            c.advance(32),
            vec![
                Step::Write { start: 24, len: 8 },
                Step::Wait { start: 16, len: 8 }
            ]
        );
    }

    #[test]
    fn a_lower_end_keeps_the_high_water_mark() {
        let mut c = Cursor::new(8);
        c.advance(16);
        assert_eq!(c.advance(4), vec![]);
        assert_eq!(
            c.advance(24),
            vec![
                Step::Write { start: 16, len: 8 },
                Step::Wait { start: 8, len: 8 }
            ]
        );
    }

    #[test]
    fn the_file_carries_every_byte_written_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let file = File::create(&path).unwrap();
        let mut w = io::BufWriter::new(WriteBehindFile::new(file));
        let chunk = vec![0xabu8; 300 * 1024];
        for _ in 0..12 {
            w.write_all(&chunk).unwrap();
        }
        w.flush().unwrap();
        w.get_ref().file().sync_data().unwrap();
        let mut back = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut back).unwrap();
        assert_eq!(back.len(), 12 * 300 * 1024);
        assert!(back.iter().all(|&b| b == 0xab));
    }
}
