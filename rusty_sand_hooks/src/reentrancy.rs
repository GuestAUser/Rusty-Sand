use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

thread_local! {
    static IN_HELPER: Cell<bool> = const { Cell::new(false) };
}

pub struct HelperGuard(PhantomData<Rc<()>>);

#[derive(Debug, PartialEq, Eq)]
pub enum EntryError {
    Reentrant,
    ThreadExiting,
}

impl HelperGuard {
    pub fn enter() -> Result<Self, EntryError> {
        IN_HELPER
            .try_with(|active| {
                if active.replace(true) {
                    Err(EntryError::Reentrant)
                } else {
                    Ok(Self(PhantomData))
                }
            })
            .map_err(|_| EntryError::ThreadExiting)?
    }
}

impl Drop for HelperGuard {
    fn drop(&mut self) {
        /* The guard cannot move to another thread. Its const TLS cell has no
        destructor, so it remains available until this scope returns. */
        let _ = IN_HELPER.try_with(|active| active.set(false));
    }
}

#[cfg(test)]
#[path = "../tests/unit/reentrancy.rs"]
mod tests;
