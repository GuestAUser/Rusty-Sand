use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Process {
    pub pid: u32,
    pub parent: Option<u32>,
    pub started: u64,
    pub name: String,
}

pub type Identity = (u32, u64);

/* Start time distinguishes ordinary PID reuse. OS timestamp granularity can
still merge processes that reuse a PID within the same timestamp unit. */
pub fn descendants(root: Identity, processes: &BTreeMap<u32, Process>) -> BTreeSet<Identity> {
    let mut found = BTreeSet::new();
    let mut pending = vec![root];

    while let Some((parent, started)) = pending.pop() {
        for process in processes.values() {
            let identity = (process.pid, process.started);

            if process.parent == Some(parent)
                && process.started >= started
                && process.pid != root.0
                && found.insert(identity)
            {
                pending.push(identity);
            }
        }
    }

    found
}

pub fn missing(tracked: &BTreeSet<Identity>, processes: &BTreeMap<u32, Process>) -> Vec<Identity> {
    tracked
        .iter()
        .copied()
        .filter(|(pid, started)| {
            processes
                .get(pid)
                .is_none_or(|process| process.started != *started)
        })
        .collect()
}

#[cfg(test)]
#[path = "../../../tests/unit/windows/monitor_process_snapshot.rs"]
mod tests;
