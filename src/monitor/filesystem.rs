use crate::config::SandboxConfig;
use crate::report::{Event, EventType};
use anyhow::{bail, Context, Result};
use log::{debug, warn};
use notify::event::{CreateKind, ModifyKind, RemoveKind};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

pub struct FileSystemMonitor {
    events: Arc<Mutex<Vec<Event>>>,
    watched_paths: Vec<PathBuf>,
}

impl FileSystemMonitor {
    pub fn new(config: SandboxConfig, events: Arc<Mutex<Vec<Event>>>) -> Result<Self> {
        let mut candidates = vec![std::env::current_dir()?, std::env::temp_dir()];

        if let Some(profile) = std::env::var_os("USERPROFILE") {
            candidates.push(PathBuf::from(&profile).join("Documents"));
            candidates.push(PathBuf::from(profile).join("Downloads"));
        }

        if let Some(working_dir) = config.working_dir {
            candidates.push(working_dir);
        }

        let mut watched_paths = Vec::<PathBuf>::new();

        for path in candidates {
            if !path.is_dir() {
                warn!("Filesystem watch directory unavailable: {}", path.display());
                continue;
            }

            let path = path
                .canonicalize()
                .with_context(|| format!("resolve watch directory {}", path.display()))?;

            if !watched_paths
                .iter()
                .any(|existing| path.starts_with(existing))
            {
                watched_paths.retain(|existing| !existing.starts_with(&path));
                watched_paths.push(path);
            }
        }

        Ok(Self {
            events,
            watched_paths,
        })
    }

    pub async fn start(self) -> Result<()> {
        let (sender, mut receiver) = mpsc::channel(1024);
        let overflow = Arc::new(AtomicBool::new(false));
        let callback_overflow = overflow.clone();
        let mut watcher = RecommendedWatcher::new(
            move |result: Result<notify::Event, notify::Error>| match sender.try_send(result) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    callback_overflow.store(true, Ordering::Release);
                }
            },
            Config::default(),
        )?;

        for path in &self.watched_paths {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .with_context(|| format!("watch directory {}", path.display()))?;
        }

        if self.watched_paths.is_empty() {
            bail!("no filesystem directories are available to watch");
        }

        let mut known_paths = HashMap::new();

        /* The watcher is owned by this future. Cancellation drops it and the
        receiver; callbacks never block an OS notification thread. */
        while let Some(result) = receiver.recv().await {
            if overflow.load(Ordering::Acquire) {
                bail!("filesystem notification queue overflowed; observations are incomplete");
            }

            let event = result.context("filesystem notification")?;

            if event.need_rescan() {
                bail!("filesystem backend lost notifications; observations are incomplete");
            }

            for path in event.paths {
                if let Some(event_type) = classify(event.kind, &path, &mut known_paths) {
                    self.events.lock().await.push(Event {
                        timestamp: chrono::Utc::now(),
                        event_type,
                        details: format!(
                            "Observed filesystem change (process unattributed): {}",
                            path.display()
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

fn classify(
    kind: EventKind,
    path: &Path,
    known_paths: &mut HashMap<PathBuf, bool>,
) -> Option<EventType> {
    if let EventKind::Remove(removal) = kind {
        let known_directory = known_paths.remove(path);
        known_paths.retain(|entry, _| !entry.starts_with(path));

        return match removal {
            RemoveKind::Folder => Some(EventType::FolderDeleted),
            RemoveKind::File => Some(EventType::FileDeleted),
            _ => match known_directory {
                Some(true) => Some(EventType::FolderDeleted),
                Some(false) => Some(EventType::FileDeleted),
                None => {
                    debug!("Unclassified removal notification: {}", path.display());
                    None
                }
            },
        };
    }

    /* Windows notifications omit entry types. Remember observed metadata for
    later removals, without assuming that an already missing path is a file.
    Eviction reduces classification coverage rather than inventing a type. */
    if let Ok(metadata) = path.metadata() {
        if metadata.is_dir() || metadata.is_file() {
            if known_paths.len() >= 65_536 && !known_paths.contains_key(path) {
                known_paths.clear();
                warn!("Filesystem type cache capacity reached; older removal types may be unknown");
            }

            known_paths.insert(path.to_owned(), metadata.is_dir());
        }
    }

    match kind {
        EventKind::Create(CreateKind::Folder) => Some(EventType::FolderCreated),
        EventKind::Create(CreateKind::File) => Some(EventType::FileCreated),
        EventKind::Create(CreateKind::Any) => match known_paths.get(path) {
            Some(true) => Some(EventType::FolderCreated),
            Some(false) => Some(EventType::FileCreated),
            None => None,
        },
        EventKind::Modify(ModifyKind::Any | ModifyKind::Data(_) | ModifyKind::Metadata(_))
            if known_paths.get(path) == Some(&false) =>
        {
            Some(EventType::FileModified)
        }
        EventKind::Modify(ModifyKind::Name(_)) => {
            /* Renames are not evidence of content changes. Invalidate the old
            name; the destination will be learned from its own metadata. */
            if !path.exists() {
                known_paths.retain(|entry, _| !entry.starts_with(path));
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/monitor_filesystem.rs"]
mod tests;
