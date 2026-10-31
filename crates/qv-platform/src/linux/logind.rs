// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authenticated system-bus lifecycle signals; no shell/command-output parser.
use crate::{Lifecycle, LockCallback, LockEvent, PlatformError, Watch};
use async_io::Timer;
use futures_lite::{StreamExt, future};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use zbus::{
    Connection, MatchRule, Message, MessageStream, Proxy,
    message::Type,
    wire::{OwnedFd, OwnedObjectPath, OwnedVariant},
};
const SERVICE: &str = "org.freedesktop.login1";
const ROOT: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";
const SESSION: &str = "org.freedesktop.login1.Session";
const DBUS: &str = "org.freedesktop.DBus";
const QUEUE: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(8) {
    Some(n) => n,
    None => std::num::NonZeroUsize::MIN,
};
const DEADLINE: Duration = Duration::from_secs(3);

/// Logind lifecycle service. Each subscription owns its connection and worker.
#[derive(Default)]
pub struct Logind {
    active: Arc<AtomicUsize>,
}
impl Logind {
    /// At least one authenticated subscription is currently active.
    pub fn is_available(&self) -> bool {
        self.active.load(Ordering::SeqCst) != 0
    }
}
struct Guard {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Watch for Guard {}
impl Drop for Guard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct Ready {
    conn: Connection,
    signals: MessageStream,
    owners: MessageStream,
    owner: String,
    session: OwnedObjectPath,
    initially_locked: bool,
    _inhibitor: OwnedFd,
}
async fn prepare(builder: zbus::connection::Builder<'_>) -> Result<Ready, PlatformError> {
    let map = |_| PlatformError::Unavailable;
    let conn = builder
        .max_queued(QUEUE)
        .method_timeout(DEADLINE)
        .build()
        .await
        .map_err(map)?;
    // Subscribe to ownership changes before resolving the service name.
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(DBUS)
        .interface(DBUS)
        .path("/org/freedesktop/DBus")
        .member("NameOwnerChanged")
        .add_arg(SERVICE)
        .build()
        .map_err(map)?;
    let owners = MessageStream::for_match_rule(rule, &conn, Some(QUEUE))
        .await
        .map_err(map)?;
    let bus = Proxy::new(&conn, DBUS, "/org/freedesktop/DBus", DBUS)
        .await
        .map_err(map)?;
    let owner: String = bus.call("GetNameOwner", &(SERVICE,)).await.map_err(map)?;
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(owner.as_str())
        .path_namespace(ROOT)
        .build()
        .map_err(map)?;
    let signals = MessageStream::for_match_rule(rule, &conn, Some(QUEUE))
        .await
        .map_err(map)?;
    let manager = Proxy::new(&conn, owner.as_str(), ROOT, MANAGER)
        .await
        .map_err(map)?;
    let session: OwnedObjectPath = manager
        .call("GetSessionByPID", &(std::process::id(),))
        .await
        .map_err(map)?;
    if !session
        .as_str()
        .starts_with("/org/freedesktop/login1/session/")
    {
        return Err(PlatformError::Unavailable);
    }
    // Get directly, without a property cache or a subscription/query gap.
    let properties = Proxy::new(
        &conn,
        owner.as_str(),
        session.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .map_err(map)?;
    let locked: OwnedVariant = properties
        .call("Get", &(SESSION, "LockedHint"))
        .await
        .map_err(map)?;
    let initially_locked = bool::try_from(locked).map_err(|_| PlatformError::Unavailable)?;
    let sleeping: OwnedVariant = Proxy::new(
        &conn,
        owner.as_str(),
        ROOT,
        "org.freedesktop.DBus.Properties",
    )
    .await
    .map_err(map)?
    .call("Get", &(MANAGER, "PreparingForSleep"))
    .await
    .map_err(map)?;
    let initially_locked =
        initially_locked || bool::try_from(sleeping).map_err(|_| PlatformError::Unavailable)?;
    // Delay suspend while the callback cancels/locks core. The OS imposes its
    // own maximum delay; this cannot establish locked-state disk-key custody.
    let inhibitor: OwnedFd = manager
        .call(
            "Inhibit",
            &("sleep", "QuickVault", "Lock vault before sleep", "delay"),
        )
        .await
        .map_err(map)?;
    let current: String = bus.call("GetNameOwner", &(SERVICE,)).await.map_err(map)?;
    if current != owner {
        return Err(PlatformError::Unavailable);
    }
    drop(manager);
    drop(bus);
    drop(properties);
    Ok(Ready {
        conn,
        signals,
        owners,
        owner,
        session,
        initially_locked,
        _inhibitor: inhibitor,
    })
}
fn classify(msg: &Message, owner: &str, session: &str) -> Result<Option<LockEvent>, PlatformError> {
    let h = msg.header();
    if h.message_type() != Type::Signal {
        return Ok(None);
    }
    let sender = h.sender().map(|s| s.as_str());
    let interface = h.interface().map(|s| s.as_str());
    let path = h.path().map(|s| s.as_str());
    let member = h.member().map(|s| s.as_str());
    if sender == Some(DBUS)
        && interface == Some(DBUS)
        && path == Some("/org/freedesktop/DBus")
        && member == Some("NameOwnerChanged")
    {
        let (name, old, new): (String, String, String) = msg
            .body()
            .deserialize()
            .map_err(|_| PlatformError::Unavailable)?;
        return Ok(
            (name == SERVICE && old == owner && new != owner).then_some(LockEvent::ProtectionLost)
        );
    }
    if sender != Some(owner) {
        return Ok(None);
    }
    if path == Some(session) && interface == Some(SESSION) && member == Some("Lock") {
        let (): () = msg
            .body()
            .deserialize()
            .map_err(|_| PlatformError::Unavailable)?;
        return Ok(Some(LockEvent::ScreenLocked));
    }
    if path == Some(ROOT) && interface == Some(MANAGER) && member == Some("PrepareForSleep") {
        let (starting,): (bool,) = msg
            .body()
            .deserialize()
            .map_err(|_| PlatformError::Unavailable)?;
        return Ok(starting.then_some(LockEvent::PreparingForSleep));
    }
    if path == Some(session)
        && interface == Some("org.freedesktop.DBus.Properties")
        && member == Some("PropertiesChanged")
    {
        let (iface, changed, invalidated): (
            String,
            std::collections::HashMap<String, OwnedVariant>,
            Vec<String>,
        ) = msg
            .body()
            .deserialize()
            .map_err(|_| PlatformError::Unavailable)?;
        if iface != SESSION {
            return Ok(None);
        }
        if invalidated.iter().any(|s| s == "LockedHint") {
            return Ok(Some(LockEvent::ProtectionLost));
        }
        if let Some(value) = changed.get("LockedHint") {
            let locked = bool::try_from(value).map_err(|_| PlatformError::Unavailable)?;
            return Ok(locked.then_some(LockEvent::ScreenLocked));
        }
    }
    Ok(None)
}
impl Lifecycle for Logind {
    fn watch(&self, callback: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
        // Pin the local system endpoint: never honor an environment-controlled
        // TCP/system-bus address for security signals.
        let builder = zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket");
        self.watch_builder(builder, callback)
    }
}
impl Logind {
    fn watch_builder(
        &self,
        builder: zbus::connection::Builder<'_>,
        callback: LockCallback,
    ) -> Result<Box<dyn Watch>, PlatformError> {
        let mut ready = future::block_on(future::race(prepare(builder), async {
            Timer::after(DEADLINE).await;
            Err(PlatformError::Unavailable)
        }))?;
        // Deliver an already-observed lock before returning the subscription:
        // scheduling the worker must not expose a briefly usable locked session.
        if ready.initially_locked {
            callback(LockEvent::ScreenLocked);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let active = self.active.clone();
        active.fetch_add(1, Ordering::SeqCst);
        let worker = std::thread::Builder::new()
            .name("qv-logind".into())
            .spawn(move || {
                future::block_on(async {
                    if ready.initially_locked {
                        callback(LockEvent::ScreenLocked);
                    } else {
                        while !stopping.load(Ordering::SeqCst) {
                            let next = future::race(
                                async { Some(ready.signals.next().await) },
                                future::race(async { Some(ready.owners.next().await) }, async {
                                    Timer::after(Duration::from_millis(100)).await;
                                    None
                                }),
                            )
                            .await;
                            if stopping.load(Ordering::SeqCst) {
                                break;
                            }
                            let Some(next) = next else {
                                continue;
                            };
                            let event = match next {
                                Some(Ok(message)) => {
                                    classify(&message, &ready.owner, ready.session.as_str())
                                        .unwrap_or(Some(LockEvent::ProtectionLost))
                                }
                                _ => Some(LockEvent::ProtectionLost),
                            };
                            if let Some(event) = event {
                                callback(event);
                                break;
                            }
                        }
                    }
                    // Release the delay inhibitor only after the lock callback.
                    drop(ready._inhibitor);
                    let _ = future::race(
                        async {
                            let _ = ready.conn.close().await;
                        },
                        async {
                            Timer::after(Duration::from_secs(1)).await;
                        },
                    )
                    .await;
                });
                active.fetch_sub(1, Ordering::SeqCst);
            })
            .map_err(|_| {
                self.active.fetch_sub(1, Ordering::SeqCst);
                PlatformError::Io
            })?;
        Ok(Box::new(Guard {
            stop,
            worker: Some(worker),
        }))
    }
}

#[cfg(test)]
mod tests {
    // Synthetic authenticated bus messages exercise dispatch without touching the desktop.
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn signal(path: &str, interface: &str, member: &str) -> zbus::message::Builder<'static> {
        Message::signal(path.to_owned(), interface.to_owned(), member.to_owned()).sender(":1.42")
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn logind_dispatch_checks_sender_session_types_and_sleep_direction() {
        let session = "/org/freedesktop/login1/session/_1";
        let lock = signal(session, SESSION, "Lock").build(&()).unwrap();
        assert_eq!(
            classify(&lock, ":1.42", session),
            Ok(Some(LockEvent::ScreenLocked))
        );
        assert_eq!(classify(&lock, ":1.43", session), Ok(None));
        assert_eq!(
            classify(&lock, ":1.42", "/org/freedesktop/login1/session/_2"),
            Ok(None)
        );
        for starting in [false, true] {
            let sleep = signal(ROOT, MANAGER, "PrepareForSleep")
                .build(&(starting,))
                .unwrap();
            assert_eq!(
                classify(&sleep, ":1.42", session),
                Ok(starting.then_some(LockEvent::PreparingForSleep))
            );
        }
        let bad = signal(ROOT, MANAGER, "PrepareForSleep")
            .build(&("bad",))
            .unwrap();
        assert!(classify(&bad, ":1.42", session).is_err());
        let properties = signal(
            session,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
        )
        .build(&(
            SESSION,
            std::collections::HashMap::<String, OwnedVariant>::new(),
            vec!["LockedHint"],
        ))
        .unwrap();
        assert_eq!(
            classify(&properties, ":1.42", session),
            Ok(Some(LockEvent::ProtectionLost))
        );
    }
    struct Manager;
    #[zbus::interface(name = "org.freedesktop.login1.Manager")]
    impl Manager {
        #[zbus(name = "GetSessionByPID")]
        fn get_session_by_pid(&self, _pid: u32) -> OwnedObjectPath {
            OwnedObjectPath::try_from("/org/freedesktop/login1/session/_1").unwrap()
        }
        #[zbus(property)]
        fn preparing_for_sleep(&self) -> bool {
            false
        }
        fn inhibit(&self, _what: &str, _who: &str, _why: &str, _mode: &str) -> OwnedFd {
            std::os::fd::OwnedFd::from(std::fs::File::open("/dev/null").unwrap()).into()
        }
    }
    struct Session(bool);
    #[zbus::interface(name = "org.freedesktop.login1.Session")]
    impl Session {
        #[zbus(property)]
        fn locked_hint(&self) -> bool {
            self.0
        }
    }
    struct Bus {
        child: std::process::Child,
        address: String,
    }
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    impl Bus {
        fn new() -> Self {
            use std::io::{BufRead, Read};
            let mut child = std::process::Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1", "--nopidfile"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut address = String::new();
                let result = std::io::BufReader::new(stdout)
                    .take(4096)
                    .read_line(&mut address);
                let _ = tx.send((result, address));
            });
            let result = rx.recv_timeout(Duration::from_secs(5));
            if result.is_err() {
                let _ = child.kill();
            }
            reader.join().unwrap();
            let (result, address) = result.unwrap();
            result.unwrap();
            Self {
                child,
                address: address.trim().into(),
            }
        }
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn logind_private_bus_events_owner_loss_and_idle_drop() {
        for action in [0, 1, 2, 3, 4] {
            let bus = Bus::new();
            let server = zbus::connection::Builder::address(bus.address.as_str())
                .name(SERVICE)
                .serve_at(ROOT, Manager)
                .serve_at("/org/freedesktop/login1/session/_1", Session(action == 4))
                .build();
            let server = future::block_on(server).unwrap();
            let service = Logind::default();
            let (tx, rx) = std::sync::mpsc::channel();
            let guard = service
                .watch_builder(
                    zbus::connection::Builder::address(bus.address.as_str()),
                    Arc::new(move |e| {
                        tx.send(e).unwrap();
                    }),
                )
                .unwrap();
            if action == 4 {
                assert_eq!(rx.try_recv().unwrap(), LockEvent::ScreenLocked);
            } else {
                assert!(service.is_available());
            }
            match action {
                0 => future::block_on(server.emit_signal(
                    None::<&str>,
                    "/org/freedesktop/login1/session/_1",
                    SESSION,
                    "Lock",
                    &(),
                ))
                .unwrap(),
                1 => future::block_on(server.emit_signal(
                    None::<&str>,
                    ROOT,
                    MANAGER,
                    "PrepareForSleep",
                    &(true,),
                ))
                .unwrap(),
                2 => {
                    future::block_on(server.release_name(SERVICE)).unwrap();
                }
                _ => {}
            }
            if action < 3 {
                let event = rx.recv_timeout(Duration::from_secs(3)).unwrap();
                assert_eq!(
                    event,
                    [
                        LockEvent::ScreenLocked,
                        LockEvent::PreparingForSleep,
                        LockEvent::ProtectionLost
                    ][action]
                );
            }
            let start = std::time::Instant::now();
            drop(guard);
            assert!(start.elapsed() < Duration::from_secs(2));
            assert!(!service.is_available());
        }
    }
    #[test]
    fn logind_stalled_authentication_is_bounded() {
        let dir = std::env::temp_dir().join(format!("qv-platform-stall-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let socket = dir.join("bus");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let address = format!("unix:path={}", socket.display());
        let start = std::time::Instant::now();
        let result = Logind::default().watch_builder(
            zbus::connection::Builder::address(address.as_str()),
            Arc::new(|_| {}),
        );
        assert!(matches!(result, Err(PlatformError::Unavailable)));
        assert!(start.elapsed() < Duration::from_secs(5));
        drop(listener);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
