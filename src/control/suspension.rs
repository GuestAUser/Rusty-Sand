// Thread suspension utilities

use windows::Win32::Foundation::HANDLE;

pub struct ThreadSuspender {
    suspended_threads: Vec<HANDLE>,
}

impl ThreadSuspender {
    pub fn new() -> Self {
        Self {
            suspended_threads: Vec::new(),
        }
    }

    pub fn add_thread(&mut self, handle: HANDLE) {
        self.suspended_threads.push(handle);
    }

    pub fn thread_count(&self) -> usize {
        self.suspended_threads.len()
    }
}

impl Default for ThreadSuspender {
    fn default() -> Self {
        Self::new()
    }
}
