use std::mem::MaybeUninit;

use block2::Block;
use dispatch2::{dispatch_block_t, DispatchQueue, DispatchQueueAttr, DispatchRetained};

pub(crate) type Queue = DispatchRetained<DispatchQueue>;

pub(crate) fn serial_queue(label: &str) -> Queue {
    DispatchQueue::new(label, DispatchQueueAttr::SERIAL)
}

pub(crate) trait DispatchQueueExt {
    fn exec_sync_with_result<T, F>(&self, work: F) -> T
    where
        F: Send + FnOnce() -> T,
        T: Send;

    fn exec_block_async(&self, block: &Block<dyn Fn()>);

    fn exec_block_sync(&self, block: &Block<dyn Fn()>);
}

impl DispatchQueueExt for DispatchQueue {
    fn exec_sync_with_result<T, F>(&self, work: F) -> T
    where
        F: Send + FnOnce() -> T,
        T: Send,
    {
        let mut result = MaybeUninit::uninit();
        self.exec_sync(|| {
            result.write(work());
        });

        // SAFETY: `dispatch_sync` only returns after the submitted closure has run.
        unsafe { result.assume_init() }
    }

    fn exec_block_async(&self, block: &Block<dyn Fn()>) {
        let block = block as *const Block<dyn Fn()> as dispatch_block_t;
        unsafe { self.exec_async_with_block(block) };
    }

    fn exec_block_sync(&self, block: &Block<dyn Fn()>) {
        let block = block as *const Block<dyn Fn()> as dispatch_block_t;
        unsafe { self.exec_sync_with_block(block) };
    }
}
