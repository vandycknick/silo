mod mount;
mod umount;

pub use mount::mount;
pub use umount::umount;

pub(crate) use mount::{mount_block_auto, mount_one};
