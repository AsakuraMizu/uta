//! Watches the cgroup tree for cgroups that rules or `uta run` care about.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
    fs, io,
    path::{Path, PathBuf},
};

use compio::runtime::fd::PollFd;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, InotifyEvent, WatchDescriptor};

pub struct Watcher {
    inotify: PollFd<Inotify>,
    targets: RefCell<HashMap<WatchDescriptor, Target>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// A directory whose children may match a cgroup pattern.
    Dir(PathBuf),
    /// The `cgroup.events` file of a `uta run` scope, relative to the cgroup
    /// root.
    Run(String),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    /// Cgroups appeared or went away under a watched directory.
    pub tree: bool,
    /// `uta run` scopes that no longer hold any process.
    pub ended: Vec<String>,
}

impl Watcher {
    pub fn new() -> io::Result<Self> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        Ok(Self {
            inotify: PollFd::new(inotify)?,
            targets: RefCell::default(),
        })
    }

    /// Watches exactly `dirs` for created and removed cgroups.
    pub fn set_dirs(&self, dirs: &BTreeSet<PathBuf>) {
        let mut targets = self.targets.borrow_mut();
        targets.retain(|wd, target| match target {
            Target::Dir(dir) if !dirs.contains(dir) => {
                let _ = self.inotify.rm_watch(*wd);
                false
            }
            _ => true,
        });
        for dir in dirs {
            if targets
                .values()
                .any(|target| *target == Target::Dir(dir.clone()))
            {
                continue;
            }
            // A directory removed since it was read needs no watch.
            if let Ok(wd) = self.inotify.add_watch(
                dir,
                AddWatchFlags::IN_CREATE | AddWatchFlags::IN_DELETE | AddWatchFlags::IN_ONLYDIR,
            ) {
                targets.insert(wd, Target::Dir(dir.clone()));
            }
        }
    }

    /// Watches a `uta run` scope until it holds no process.
    pub fn add_run(&self, root: &Path, cgroup: &str) -> io::Result<()> {
        let wd = self.inotify.add_watch(
            &root.join(cgroup).join("cgroup.events"),
            AddWatchFlags::IN_MODIFY,
        )?;
        self.targets
            .borrow_mut()
            .insert(wd, Target::Run(cgroup.to_owned()));
        Ok(())
    }

    pub fn remove_run(&self, cgroup: &str) {
        self.targets.borrow_mut().retain(|wd, target| {
            if *target == Target::Run(cgroup.to_owned()) {
                let _ = self.inotify.rm_watch(*wd);
                false
            } else {
                true
            }
        });
    }

    /// Waits for events, then reports what changed.
    pub async fn changes(&self, root: &Path) -> io::Result<Changes> {
        let events = std::future::poll_fn(|cx| {
            self.inotify
                .poll_read_with(cx, |inotify| inotify.read_events().map_err(io::Error::from))
        })
        .await?;
        let mut changes = Changes::default();
        self.classify(events, root, &mut changes);
        Ok(changes)
    }

    /// Adds the events that are already queued to `changes`, without waiting.
    pub fn drain(&self, root: &Path, changes: &mut Changes) -> io::Result<()> {
        match self.inotify.read_events() {
            Ok(events) => self.classify(events, root, changes),
            Err(nix::Error::EAGAIN) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn classify(&self, events: Vec<InotifyEvent>, root: &Path, changes: &mut Changes) {
        let targets = self.targets.borrow();
        for event in events {
            if event.mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
                changes.tree = true;
                for target in targets.values() {
                    if let Target::Run(cgroup) = target
                        && !populated(root, cgroup)
                    {
                        changes.ended.push(cgroup.clone());
                    }
                }
                continue;
            }
            match targets.get(&event.wd) {
                Some(Target::Dir(_)) => changes.tree = true,
                // IN_IGNORED follows the removal of the scope.
                Some(Target::Run(cgroup))
                    if event.mask.contains(AddWatchFlags::IN_IGNORED)
                        || !populated(root, cgroup) =>
                {
                    changes.ended.push(cgroup.clone());
                }
                _ => {}
            }
        }
        changes.ended.sort();
        changes.ended.dedup();
    }
}

/// Whether a cgroup holds a process, from `populated` in its `cgroup.events`.
pub fn populated(root: &Path, cgroup: &str) -> bool {
    fs::read_to_string(root.join(cgroup).join("cgroup.events"))
        .is_ok_and(|events| events.lines().any(|line| line == "populated 1"))
}
