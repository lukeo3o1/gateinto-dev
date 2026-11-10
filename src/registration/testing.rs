use std::path::{Path, PathBuf};

use super::files::euid;

pub(crate) fn mkfifo(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: path is a NUL-terminated string that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

// Root owns every directory it creates, so a foreign directory is made by handing a scratch
// directory to nobody; any other user meets one in `/`.
pub(crate) fn foreign_dir(scratch: &Path) -> PathBuf {
    if euid() != 0 {
        return PathBuf::from("/");
    }
    let dir = scratch.join("foreign");
    std::fs::create_dir(&dir).unwrap();
    std::os::unix::fs::chown(&dir, Some(65534), Some(65534)).unwrap();
    dir
}
