use crate::config::SandboxConfig;
use crate::report::{Event, EventType};
use anyhow::Result;
use log::debug;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct FileSystemMonitor {
    config: SandboxConfig,
    events: Arc<Mutex<Vec<Event>>>,
    watched_paths: Vec<PathBuf>,
}

impl FileSystemMonitor {
    pub fn new(config: SandboxConfig, events: Arc<Mutex<Vec<Event>>>) -> Result<Self> {
        let mut watched_paths = vec![
            std::env::current_dir()?,
            PathBuf::from(std::env::var("TEMP")?),
            PathBuf::from(std::env::var("USERPROFILE")?).join("Documents"),
            PathBuf::from(std::env::var("USERPROFILE")?).join("Downloads"),
        ];

        // Add working directory if specified
        if let Some(ref working_dir) = config.working_dir {
            watched_paths.push(working_dir.clone());
        }

        Ok(Self {
            config,
            events,
            watched_paths,
        })
    }

    pub async fn start(self) -> Result<()> {
        debug!("Starting filesystem monitor");

        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        )?;

        // Watch key directories
        for path in &self.watched_paths {
            if path.exists() {
                match watcher.watch(path, RecursiveMode::Recursive) {
                    Ok(_) => debug!("Watching directory: {}", path.display()),
                    Err(e) => debug!("Could not watch {}: {}", path.display(), e),
                }
            }
        }

        // Process events
        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(event) => {
                    self.handle_fs_event(event).await;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Continue monitoring
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
                Err(_) => break,
            }
        }

        Ok(())
    }

    async fn handle_fs_event(&self, event: notify::Event) {
        for path in event.paths {
            // Determine if this is a file or directory
            let is_dir = path.is_dir();

            let event_type = match event.kind {
                EventKind::Create(_) => {
                    if is_dir {
                        EventType::FolderCreated
                    } else {
                        EventType::FileCreated
                    }
                }
                EventKind::Modify(_) => {
                    // Skip directory modifications (too noisy)
                    if is_dir {
                        continue;
                    }
                    EventType::FileModified
                }
                EventKind::Remove(_) => {
                    // Check metadata from event attributes if path no longer exists
                    if is_dir {
                        EventType::FolderDeleted
                    } else {
                        EventType::FileDeleted
                    }
                }
                _ => continue,
            };

            let details = format!("{}", path.display());

            if self.config.verbose {
                debug!("[FS] {:?}: {}", event_type, details);
            }

            let ev = Event {
                timestamp: chrono::Utc::now(),
                event_type,
                details,
            };

            self.events.lock().await.push(ev);
        }
    }
}
