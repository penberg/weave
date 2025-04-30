//! Memory-mapped file handling.
//!
//! This module provides utilities for mapping executable files into memory using
//! the operating system's `mmap` system call. Memory mapping allows efficient
//! access to file contents without loading the entire file into memory at once.
//!
//! The primary use case is loading ELF binaries and shared libraries for execution,
//! where the file contents need to be accessible as raw bytes for parsing and
//! translation.

use crate::Result;
use std::ffi::CString;

/// A memory-mapped file.
pub struct MappedFile {
    pub(crate) fd: libc::c_int,
    addr: *const libc::c_void,
    size: libc::off_t,
    pub data: &'static [u8],
}

impl MappedFile {
    /// Open a file and return a `MappedFile` object.
    pub fn open(path: &str) -> Result<MappedFile> {
        let c_path = CString::new(path).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains null byte")
        })?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
        let stat_ret = unsafe { libc::fstat(fd, &mut statbuf as *mut libc::stat) };
        if stat_ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if (statbuf.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe {
                libc::close(fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file",
            )
            .into());
        }
        let size = statbuf.st_size;
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size as usize,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
        };
        if addr.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let data = unsafe { std::slice::from_raw_parts(addr as *const u8, size as usize) };
        Ok(Self {
            fd,
            addr,
            size,
            data,
        })
    }

    /// Close the mapped file.
    fn close(&mut self) {
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size as usize);
            libc::close(self.fd);
        }
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        self.close();
    }
}
