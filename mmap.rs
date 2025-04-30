pub struct MappedFile {
    pub(crate) fd: libc::c_int,
    addr: *const libc::c_void,
    size: libc::off_t,
    pub data: &'static [u8],
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        self.close();
    }
}

impl MappedFile {
    /// Open a file and return a `MappedFile` object.
    pub fn open(path: &str) -> Result<MappedFile, std::io::Error> {
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
        let stat_ret = unsafe { libc::fstat(fd, &mut statbuf as *mut libc::stat) };
        if stat_ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if (statbuf.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe {
                libc::close(fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
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
            return Err(std::io::Error::last_os_error());
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
