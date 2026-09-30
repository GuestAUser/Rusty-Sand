use super::*;

fn process(pid: u32, parent: u32, started: u64) -> Process {
    Process {
        pid,
        parent: Some(parent),
        started,
        name: String::new(),
    }
}

#[test]
fn finds_descendants_but_excludes_older_reused_parent_relationships() {
    let processes = BTreeMap::from([
        (2, process(2, 1, 10)),
        (3, process(3, 2, 11)),
        (4, process(4, 1, 2)),
    ]);
    assert_eq!(
        descendants((1, 9), &processes),
        BTreeSet::from([(2, 10), (3, 11)])
    );
}

#[test]
fn reused_pid_terminates_previous_identity() {
    let tracked = BTreeSet::from([(2, 10), (3, 11)]);
    let processes = BTreeMap::from([(2, process(2, 1, 12)), (3, process(3, 9, 11))]);
    assert_eq!(missing(&tracked, &processes), vec![(2, 10)]);
}

#[test]
fn cyclic_parent_snapshot_is_bounded() {
    let processes = BTreeMap::from([(2, process(2, 1, 1)), (1, process(1, 2, 1))]);
    assert_eq!(descendants((1, 1), &processes), BTreeSet::from([(2, 1)]));
}
