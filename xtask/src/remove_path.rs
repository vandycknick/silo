use std::fs;
use std::io;
use std::path::Path;

pub(crate) fn remove_if_exists(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use crate::remove_path::remove_if_exists;

    #[test]
    fn removes_directories_and_symlinks_without_following_them() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let output = temp.path().join("output");
        std::fs::create_dir(&output).expect("create output directory");
        std::fs::write(output.join("stale"), b"stale").expect("write stale output");
        remove_if_exists(&output).expect("remove output directory");
        remove_if_exists(&output).expect("ignore missing output");

        let retained = temp.path().join("retained");
        std::fs::create_dir(&retained).expect("create retained directory");
        std::os::unix::fs::symlink(&retained, &output).expect("create output symlink");
        remove_if_exists(&output).expect("remove output symlink");
        assert!(retained.is_dir());
        assert!(!output.exists());
    }
}
