//! The internal edit queue facilitating native <-> webview communication.
//!
//! Originally, we used long-polling on the wry custom protocol to send edits to the webview.
//! Due to bugs in wry on android, we switched to a websocket connection that the webview connects to.
//! We use the sledgehammer crate to build batches of edits and send them through the websocket to
//! the webview.
//!
//! Using a websocket lets us send binary data to the webview quite efficiently and does encounter
//! many of the issues with regular request/response protocols. Note that the websocket max frame
//! size is quite large (9.22 exabytes), so we can have very large batches without issue.
//!
//! Using websockets does mean we need to handle security and content security policies ourselves.
//! The code here generates a random key that the webview must use to connect to the websocket.
//! We use the initialization script API to setup the websocket connection without leaking the key
//! to the webview itself in case there's untrusted content in the webview.
//!
//! Some operating systems (like iOS) will kill the websocket connection when the device goes to sleep.
//! If this happens, we will automatically switch to a new port and notify the webview of the new location
//! and key. The webview will then reconnect to the new port and continue receiving edits.

use dioxus_interpreter_js::MutationState;
use futures_channel::oneshot;
use futures_util::FutureExt;
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{TcpListener, TcpStream};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::AtomicU32;
use std::sync::Mutex;
use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
};
use tokio::sync::Notify;

// Bound reads before the websocket handshake parser can grow its buffer.
struct HandshakeStream {
    inner: TcpStream,
    remaining: Option<usize>,
}
impl std::io::Read for HandshakeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let max = buf.len().min(self.remaining.unwrap_or(usize::MAX));
        if max == 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let n = std::io::Read::read(&mut self.inner, &mut buf[..max])?;
        if let Some(left) = &mut self.remaining {
            *left -= n;
        }
        Ok(n)
    }
}
impl std::io::Write for HandshakeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.inner, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.inner)
    }
}
static ACTIVE_CONNECTIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct ConnectionPermit;
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// This handles communication between the requests that the webview makes and the interpreter.
#[derive(Clone)]
pub(crate) struct WryQueue {
    // Protocol callbacks on Android may run while the renderer borrows inner.
    // Connection metadata is independently shared and never borrows edit state.
    location: WebviewWebsocketLocation,
    inner: Rc<RefCell<WryQueueInner>>,
}

impl WryQueue {
    pub(crate) fn with_mutation_state_mut<O: 'static>(
        &self,
        callback: impl FnOnce(&mut MutationState) -> O,
    ) -> O {
        let mut inner = self.inner.borrow_mut();
        callback(&mut inner.mutation_state)
    }

    /// Send a list of mutations to the webview
    pub(crate) fn send_edits(&self) {
        let mut myself = self.inner.borrow_mut();
        let webview_id = myself.location.webview_id;
        let serialized_edits = myself.mutation_state.export_memory();
        let receiver = myself.websocket.send_edits(webview_id, serialized_edits);
        myself.edits_in_progress = Some(receiver);
    }

    /// Wait until all pending edits have been rendered in the webview.
    /// `Ready(false)` means the batch was dropped before the webview applied it.
    pub(crate) fn poll_edits_flushed(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<bool> {
        let mut self_mut = self.inner.borrow_mut();
        let Some(receiver) = self_mut.edits_in_progress.as_mut() else {
            return std::task::Poll::Ready(true);
        };
        // A resolved oneshot reports `Canceled` when polled again, so forget it
        // once it resolves instead of reading a later poll as a dropped batch.
        let applied = std::task::ready!(receiver.poll_unpin(cx)).is_ok();
        self_mut.edits_in_progress = None;
        std::task::Poll::Ready(applied)
    }

    /// Check if there is a new location for the websocket edits server.
    pub(crate) fn poll_new_edits_location(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let mut self_mut = self.inner.borrow_mut();
        let poll = self_mut
            .server_location_changed_future
            .as_mut()
            .poll_unpin(cx);
        if poll.is_ready() {
            // If the future is ready, we need to reset it to wait for the next change
            self_mut.server_location_changed_future =
                owned_notify_future(self_mut.server_location_changed.clone());
        }
        poll
    }

    /// Get the websocket path that the webview should connect to in order to receive edits
    pub(crate) fn edits_path(&self) -> String {
        let WebviewWebsocketLocation {
            webview_id, server, ..
        } = &self.location;
        let server = server.lock().unwrap();
        let port = server.port;
        let key = &server.client_key;
        let key_hex = encode_key_string(key);
        format!("ws://127.0.0.1:{port}/{webview_id}/{key_hex}")
    }

    /// Get the key the client should expect from the server when connecting to the websocket.
    pub(crate) fn required_server_key(&self) -> String {
        let server = &self.location.server;
        let server = server.lock().unwrap();
        encode_key_string(&server.server_key)
    }
}

pub(crate) struct WryQueueInner {
    location: WebviewWebsocketLocation,
    websocket: EditWebsocket,
    // If this webview is currently waiting for an edit to be flushed. We don't run the virtual dom while this is true to avoid running effects before the dom has been updated
    edits_in_progress: Option<oneshot::Receiver<()>>,
    // The socket may be killed by the OS while running. If it does, this channel will receive the new server location
    server_location_changed: Arc<Notify>,
    server_location_changed_future: Pin<Box<dyn Future<Output = ()>>>,
    mutation_state: MutationState,
}

/// The location of a webview websocket connection. This is used to identify the webview and the port it is connected to.
#[derive(Clone)]
pub(crate) struct WebviewWebsocketLocation {
    /// The id of the webview that this websocket is connected to
    webview_id: u32,
    server: Arc<Mutex<ServerLocation>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ServerLocation {
    /// The port the websocket is on
    port: u16,
    /// A key that every websocket connection that originates from this application will use to identify itself.
    /// We use this to make sure no external applications can connect to our websocket and receive UI updates.
    client_key: [u8; KEY_SIZE],
    /// The key that the server must respond with for the client to connect to the websocket
    server_key: [u8; KEY_SIZE],
}

/// Start a new server on an available port on localhost. Return the server location and the TCP listener that is bound to the port.
pub(crate) fn start_server() -> (ServerLocation, TcpListener) {
    let client_key = create_secure_key();
    let server_key = create_secure_key();
    let server = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .expect("Failed to bind local TCP listener for edit socket");
    let port = server.local_addr().unwrap().port();
    let location = ServerLocation {
        port,
        client_key,
        server_key,
    };
    (location, server)
}

/// The websocket listener that the webview will connect to in order to receive edits and send requests. There
/// is only one websocket listener per application even if there are multiple windows so we don't use all the
/// open ports.
#[derive(Clone)]
pub(crate) struct EditWebsocket {
    current_location: Arc<Mutex<ServerLocation>>,
    max_webview_id: Arc<AtomicU32>,
    connections: Arc<RwLock<HashMap<u32, WebviewConnectionState>>>,
    server_location: Arc<Notify>,
}

impl EditWebsocket {
    pub(crate) fn start(hardened: bool) -> Self {
        let connections = Arc::new(RwLock::new(HashMap::new()));

        let notify = Arc::new(Notify::new());
        let (location, server) = start_server();
        let current_location = Arc::new(Mutex::new(location));

        let connections_ = connections.clone();
        let current_location_ = current_location.clone();
        let notify_ = notify.clone();
        std::thread::spawn(move || {
            Self::accept_loop(notify_, server, current_location_, connections_, hardened)
        });

        Self {
            connections,
            max_webview_id: Default::default(),
            current_location,
            server_location: notify,
        }
    }

    /// Accepts incoming websocket connections and handles them in a loop.
    ///
    /// New sockets are accepted and then put in to a new thread to handle the connection.
    /// This is implemented using traditional sync code to allow us to be independent of the async runtime.
    fn accept_loop(
        notify: Arc<Notify>,
        mut server: TcpListener,
        current_location: Arc<Mutex<ServerLocation>>,
        connections: Arc<RwLock<HashMap<u32, WebviewConnectionState>>>,
        hardened: bool,
    ) {
        loop {
            // Accept connections until we hit an error
            while let Ok((stream, _)) = server.accept() {
                Self::handle_connection(
                    stream,
                    current_location.clone(),
                    connections.clone(),
                    hardened,
                );
            }

            // Switch ports and reconnect on a different port if the server is killed by the OS. This
            // will happen if an IOS device goes to sleep
            //
            // For security, it is important that the keys are also regenerated when the server is restarted.
            // The client may try to reconnect to the old port that is now being used by an attacker who steals the client
            // key and uses it to read the edits from the new port.
            let (location, new_server) = start_server();
            notify.notify_waiters();
            *current_location.lock().unwrap() = location;
            server = new_server;
        }
    }

    fn handle_connection(
        stream: TcpStream,
        server_location: Arc<Mutex<ServerLocation>>,
        connections: Arc<RwLock<HashMap<u32, WebviewConnectionState>>>,
        hardened: bool,
    ) {
        use tungstenite::handshake::server::{Request, Response};
        let permit = if hardened {
            if ACTIVE_CONNECTIONS
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| (n < 4).then_some(n + 1),
                )
                .is_err()
            {
                return;
            }
            let permit = ConnectionPermit;
            if stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .and_then(|()| stream.set_write_timeout(Some(std::time::Duration::from_secs(3))))
                .is_err()
            {
                return;
            }
            Some(permit)
        } else {
            None
        };
        let stream = HandshakeStream {
            inner: stream,
            remaining: hardened.then_some(8192),
        };

        let current_server_location = { *server_location.lock().unwrap() };
        let hex_encoded_client_key = encode_key_string(&current_server_location.client_key);
        let hex_encoded_server_key = encode_key_string(&current_server_location.server_key);
        let mut location = None;

        #[allow(clippy::result_large_err)]
        let on_request = |req: &Request, res| {
            // Try to parse the webview id and key from the path
            let path = req.uri().path();

            // The path should have two parts `/webview_id/key`
            let mut segments = path.trim_matches('/').split('/');
            let webview_id = segments
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or_else(|| {
                    Response::builder()
                        .status(400)
                        .body(Some("Bad Request: Invalid webview ID".to_string()))
                        .unwrap()
                })?;
            if hardened && !connections.read().unwrap().contains_key(&webview_id) {
                return Err(Response::builder()
                    .status(400)
                    .body(Some("Unknown view".to_string()))
                    .unwrap());
            }
            let key = segments.next().ok_or_else(|| {
                Response::builder()
                    .status(400)
                    .body(Some("Bad Request: Missing key".to_string()))
                    .unwrap()
            })?;

            if hardened && segments.next().is_some() {
                return Err(Response::builder()
                    .status(400)
                    .body(Some("Bad request".to_string()))
                    .unwrap());
            }
            // Make sure the key matches the expected key.
            // VERY IMPORTANT: We cannot use normal string comparison here because it reveals information
            // about the key based on timing information. Instead we use a constant time comparison method.
            let key_matches: bool =
                subtle::ConstantTimeEq::ct_eq(hex_encoded_client_key.as_ref(), key.as_bytes())
                    .into();
            if !key_matches {
                return Err(Response::builder()
                    .status(403)
                    .body(Some("Forbidden: Invalid key".to_string()))
                    .unwrap());
            }

            location = Some(WebviewWebsocketLocation {
                webview_id,
                server: server_location,
            });

            Ok(res)
        };

        // Accept the websocket connection while reading the path and setting the location
        let mut websocket = match tungstenite::accept_hdr_with_config(
            stream,
            on_request,
            hardened.then(|| {
                tungstenite::protocol::WebSocketConfig::default()
                    .read_buffer_size(1024)
                    .max_frame_size(Some(1024))
                    .max_message_size(Some(1024))
            }),
        ) {
            Ok(ws) => ws,
            Err(_) => {
                tracing::error!("UI transport handshake refused");
                return;
            }
        };

        websocket.get_mut().remaining = None;
        // Immediately send the key to authenticate the server
        if websocket
            .send(tungstenite::Message::Text(hex_encoded_server_key.into()))
            .is_err()
        {
            return;
        }

        let location = match location {
            Some(loc) => loc,
            None => {
                tracing::error!("WebSocket connection without a valid webview ID");
                return;
            }
        };

        // Handle the websocket connection in a separate thread
        let (edits_outgoing, edits_incoming_rx) = std::sync::mpsc::sync_channel::<MsgPair>(2);

        let connections_ = connections.clone();
        // Spawn a task to handle the websocket connection
        std::thread::spawn(move || {
            let _permit = permit;
            let mut queued_message = None;
            // Wait until there are edits ready to send
            'connection: while let Ok(msg) = edits_incoming_rx.recv() {
                let data = msg.edits.clone();
                queued_message = Some(msg);
                // Send the edits to the webview
                if websocket
                    .send(tungstenite::Message::Binary(data.into()))
                    .is_err()
                {
                    tracing::error!("UI transport write failed");
                    break 'connection;
                }

                // Wait for the webview to apply the edits
                let mut acknowledged = false;
                while let Ok(ws_msg) = websocket.read() {
                    match ws_msg {
                        // We expect the webview to send a binary message when it has applied the edits
                        // This is a signal that we can continue processing
                        tungstenite::Message::Binary(ref b) if !hardened || b.is_empty() => {
                            acknowledged = true;
                            break;
                        }
                        // If the websocket closes, switch back to the pending state and
                        // re-queue the edits that haven't been acknowledged yet
                        tungstenite::Message::Close(_) => {
                            break 'connection;
                        }
                        _ if hardened => break 'connection,
                        _ => {}
                    }
                }

                if !acknowledged {
                    break 'connection;
                }
                let msg = queued_message.take().expect("Message should be set here");

                // Notify that the edits have been applied
                if msg.response.send(()).is_err() {
                    tracing::error!("Error sending edits applied notification");
                }
            }
            tracing::trace!("Webview {} closed the connection", location.webview_id);
            let mut connection = WebviewConnectionState::default();
            if let Some(msg) = queued_message {
                connection.add_message_pair(msg);
            }
            connections_
                .write()
                .unwrap()
                .insert(location.webview_id, connection);
        });

        let mut connections = connections.write().unwrap();
        match connections.remove(&location.webview_id) {
            // If there are pending edits, send them to the new connection
            Some(WebviewConnectionState::Pending { mut pending }) => {
                while let Some(pair) = pending.pop_front() {
                    _ = edits_outgoing.try_send(pair);
                }
            }

            // If the webview was already connected, never send edits from the old connection to
            // the new connection. This should never happen
            Some(WebviewConnectionState::Connected { .. }) => {
                tracing::error!(
                    "Webview {} was already connected. Rejecting new connection.",
                    location.webview_id
                );
                return;
            }

            None => {}
        }

        connections.insert(
            location.webview_id,
            WebviewConnectionState::Connected { edits_outgoing },
        );
    }

    pub(crate) fn create_queue(&self) -> WryQueue {
        let webview_id = self
            .max_webview_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.connections
            .write()
            .unwrap()
            .entry(webview_id)
            .or_default();
        let server = self.current_location.clone();
        let server_location = self.server_location.clone();
        WryQueue {
            location: WebviewWebsocketLocation {
                webview_id,
                server: server.clone(),
            },
            inner: Rc::new(RefCell::new(WryQueueInner {
                server_location_changed: server_location.clone(),
                server_location_changed_future: owned_notify_future(server_location),
                location: WebviewWebsocketLocation { webview_id, server },
                websocket: self.clone(),
                edits_in_progress: None,
                mutation_state: MutationState::default(),
            })),
        }
    }

    fn send_edits(&mut self, webview: u32, edits: Vec<u8>) -> oneshot::Receiver<()> {
        let mut connections_mut = self.connections.write().unwrap();
        let connection = connections_mut.entry(webview).or_default();
        connection.add_message(edits)
    }
}

/// The state of a webview websocket connection. This may be pending while the webview is booting.
/// If it is, we queue up edits until the webview is ready to receive them.
enum WebviewConnectionState {
    Pending {
        pending: VecDeque<MsgPair>,
    },
    Connected {
        edits_outgoing: std::sync::mpsc::SyncSender<MsgPair>,
    },
}

impl Default for WebviewConnectionState {
    fn default() -> Self {
        WebviewConnectionState::Pending {
            pending: VecDeque::new(),
        }
    }
}

impl WebviewConnectionState {
    /// Add a message to the active connection or queue and return a receiver that will be resolved
    /// when the webview has applied the edits.
    fn add_message(&mut self, edits: Vec<u8>) -> oneshot::Receiver<()> {
        let (response_sender, response_receiver) = oneshot::channel();
        let pair = MsgPair {
            edits,
            response: response_sender,
        };
        self.add_message_pair(pair);
        response_receiver
    }

    /// Add a message pair to the connection state. The receiver in the message pair will be resolved
    /// when the webview has applied the edits.
    fn add_message_pair(&mut self, pair: MsgPair) {
        if pair.edits.len() > 8 * 1024 * 1024 {
            return;
        }
        match self {
            WebviewConnectionState::Pending { pending: queue } => {
                if queue.len() < 2 && pair.edits.len() <= 8 * 1024 * 1024 {
                    queue.push_back(pair);
                }
            }
            WebviewConnectionState::Connected { edits_outgoing } => {
                _ = edits_outgoing.try_send(pair);
            }
        }
    }
}

struct MsgPair {
    edits: Vec<u8>,
    response: oneshot::Sender<()>,
}

const KEY_SIZE: usize = 256;
type EncodedKey = [u8; KEY_SIZE];

/// Base64 encode the key to a string to be used in the websocket URL.
fn encode_key_string(key: &EncodedKey) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, key)
}

/// Create a secure key for the websocket connection.
/// Returns the key as a byte array and a hex-encoded string representation of the key.
fn create_secure_key() -> EncodedKey {
    // Helper function to assert that the RNG is a CryptoRng - make sure we use a secure RNG
    fn assert_crypto_random<R: rand::CryptoRng>(val: R) -> R {
        val
    }

    let mut secure_rng = assert_crypto_random(rand::rngs::StdRng::from_os_rng());
    let mut expected_key: EncodedKey = [0u8; KEY_SIZE];
    secure_rng.fill_bytes(&mut expected_key);
    expected_key
}

#[test]
fn test_key_encoding_length() {
    let mut rand = rand::rngs::StdRng::from_os_rng();
    for _ in 0..100 {
        let mut key: EncodedKey = [0u8; KEY_SIZE];
        rand.fill_bytes(&mut key);
        let encoded = encode_key_string(&key);
        // The encoded key length should be the same regardless of the value of the key
        assert_eq!(encoded.len(), 344);
    }
}

// Take an Arc<Notify> and create a future that waits for the notify to be triggered.
fn owned_notify_future(notify: Arc<Notify>) -> Pin<Box<dyn Future<Output = ()>>> {
    let mut notify_owned = Box::pin(async move {
        let notified = notify.notified();

        // The future should be after this statement once it is polled bellow
        tokio::task::yield_now().await;
        notified.await;
    });

    // Start tracking notify before the output future is polled
    _ = (&mut notify_owned).now_or_never();
    notify_owned
}

#[cfg(test)]
mod hardened_transport_tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn hardened_protocol_metadata_does_not_borrow_the_active_render_queue() {
        let queue = EditWebsocket::start(true).create_queue();
        let _rendering = queue.inner.borrow_mut();
        let first = queue.edits_path();
        assert!(first.starts_with("ws://127.0.0.1:"));
        assert!(!queue.required_server_key().is_empty());
        // Keep the shared location live: a server restart must update CSP too.
        let old_port = queue.location.server.lock().unwrap().port;
        let next_port = if old_port == u16::MAX {
            1
        } else {
            old_port + 1
        };
        queue.location.server.lock().unwrap().port = next_port;
        assert!(queue
            .edits_path()
            .starts_with(&format!("ws://127.0.0.1:{next_port}/")));
        assert_ne!(first, queue.edits_path());
    }
    // A batch the bounded queue cannot hold must not look flushed: its
    // receiver resolves as cancelled, which hardened rendering treats as fatal.
    #[test]
    fn hardened_dropped_batches_resolve_as_not_applied() {
        let mut state = WebviewConnectionState::default();
        let mut kept: Vec<_> = (0..2).map(|_| state.add_message(vec![1])).collect();
        let mut dropped = state.add_message(vec![2]);
        assert!(matches!(dropped.try_recv(), Err(oneshot::Canceled)));
        let mut huge = state.add_message(vec![0; 8 * 1024 * 1024 + 1]);
        assert!(matches!(huge.try_recv(), Err(oneshot::Canceled)));
        assert!(kept.iter_mut().all(|r| matches!(r.try_recv(), Ok(None))));
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let mut full = WebviewConnectionState::Connected { edits_outgoing: tx };
        let mut lost = full.add_message(vec![3]);
        assert!(matches!(lost.try_recv(), Err(oneshot::Canceled)));
        drop(rx);
    }
    #[test]
    fn hardened_applied_batch_stays_applied_on_later_polls() {
        let queue = EditWebsocket::start(true).create_queue();
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let (applied, rx) = oneshot::channel();
        queue.inner.borrow_mut().edits_in_progress = Some(rx);
        assert!(queue.poll_edits_flushed(&mut cx).is_pending());
        applied.send(()).unwrap();
        // Later wake-ups without a new batch must not look like a dropped one.
        for _ in 0..3 {
            assert_eq!(
                queue.poll_edits_flushed(&mut cx),
                std::task::Poll::Ready(true)
            );
        }
        let (dropped, rx) = oneshot::channel::<()>();
        queue.inner.borrow_mut().edits_in_progress = Some(rx);
        drop(dropped);
        assert_eq!(
            queue.poll_edits_flushed(&mut cx),
            std::task::Poll::Ready(false)
        );
    }
    #[test]
    fn hardened_handshake_reader_and_actual_stalled_peer_are_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut bounded = HandshakeStream {
            inner: stream,
            remaining: Some(4),
        };
        peer.write_all(b"abcdefgh").unwrap();
        let mut data = [0; 16];
        assert_eq!(std::io::Read::read(&mut bounded, &mut data).unwrap(), 4);
        assert!(std::io::Read::read(&mut bounded, &mut data).is_err());
        drop(bounded);
        drop(peer);
        let (location, listener) = start_server();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let start = std::time::Instant::now();
        EditWebsocket::handle_connection(
            stream,
            Arc::new(Mutex::new(location)),
            Arc::new(RwLock::new(HashMap::new())),
            true,
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        drop(peer);
    }
}
