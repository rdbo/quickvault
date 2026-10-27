// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foreground X11 clipboard owner. No clipboard readback or manager handover.
mod transport;
use crate::{
    cli::Ctx,
    exit::{CliError, LIMIT, OTHER},
    out::Out,
};
use clap::ArgMatches;
use qv_core::SecretBytes;
use std::time::{Duration, Instant};
use transport::Connection;
use x11rb::{
    CURRENT_TIME, NONE,
    connection::Connection as _,
    protocol::{Event, xproto::*},
    wrapper::ConnectionExt as _,
};

const MAX_VALUE: usize = 256 * 1024;
const MAX_TRANSFERS: usize = 16;
#[derive(Clone, Copy)]
pub(crate) struct ClipboardOptions {
    timeout: Duration,
}
pub(crate) fn options(ctx: &Ctx, matches: &ArgMatches) -> Result<ClipboardOptions, CliError> {
    if ctx.json {
        return Err(CliError::usage(
            "--json cannot be combined with clipboard output",
        ));
    }
    let config = ctx.env.config()?;
    let seconds = matches
        .try_get_one::<u32>("timeout")
        .ok()
        .flatten()
        .copied()
        .or(config.clipboard_timeout)
        .unwrap_or(20);
    if !(1..=300).contains(&seconds) {
        return Err(CliError::usage(
            "clipboard timeout must be 1 to 300 seconds",
        ));
    }
    Ok(ClipboardOptions {
        timeout: Duration::from_secs(u64::from(seconds)),
    })
}
fn backend<T, E>(value: Result<T, E>) -> Result<T, CliError> {
    value.map_err(|_| {
        CliError::new(
            OTHER,
            "clipboard backend failed or is unavailable (requires local X11)",
        )
    })
}
struct Atoms {
    clipboard: Atom,
    targets: Atom,
    utf8: Atom,
    mime: Atom,
    plain: Atom,
    hint: Atom,
    incr: Atom,
    timestamp: Atom,
}
impl Atoms {
    fn new(c: &Connection) -> Result<Self, CliError> {
        let atom = |name: &[u8]| -> Result<Atom, CliError> {
            Ok(backend(backend(c.intern_atom(false, name))?.reply())?.atom)
        };
        Ok(Self {
            clipboard: atom(b"CLIPBOARD")?,
            targets: atom(b"TARGETS")?,
            utf8: atom(b"UTF8_STRING")?,
            mime: atom(b"text/plain;charset=utf-8")?,
            plain: atom(b"text/plain")?,
            hint: atom(b"x-kde-passwordManagerHint")?,
            incr: atom(b"INCR")?,
            timestamp: atom(b"QV_CLIPBOARD_TIMESTAMP")?,
        })
    }
    fn supported(&self) -> [Atom; 5] {
        [self.targets, self.utf8, self.mime, self.plain, self.hint]
    }
}
struct Transfer {
    window: Window,
    property: Atom,
    target: Atom,
    offset: usize,
    deadline: Instant,
}
struct Owner {
    conn: Connection,
    window: Window,
    atoms: Atoms,
    transfers: Vec<Transfer>,
    chunk: usize,
    acquired_at: u32,
}
impl Owner {
    fn new() -> Result<Self, CliError> {
        let (conn, screen) = backend(transport::connect())?;
        let root = conn.setup().roots[screen].root;
        let window = backend(conn.generate_id())?;
        backend(
            backend(conn.create_window(
                0,
                window,
                root,
                0,
                0,
                1,
                1,
                0,
                WindowClass::INPUT_ONLY,
                0,
                &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
            ))?
            .check(),
        )?;
        let atoms = Atoms::new(&conn)?;
        backend(
            backend(conn.change_property8(
                PropMode::REPLACE,
                window,
                atoms.timestamp,
                AtomEnum::INTEGER,
                &[],
            ))?
            .check(),
        )?;
        let acquired_at = loop {
            if let Event::PropertyNotify(event) = backend(conn.wait_for_event())?
                && event.window == window
                && event.atom == atoms.timestamp
            {
                break event.time;
            }
        };
        // Keep requests below the core protocol limit; no BIG-REQUESTS query is needed.
        let chunk = 16_384usize.min(
            usize::from(conn.setup().maximum_request_length)
                .saturating_mul(4)
                .saturating_sub(24),
        );
        if chunk == 0 {
            return Err(CliError::new(OTHER, "X11 request limit is too small"));
        }
        Ok(Self {
            conn,
            window,
            atoms,
            transfers: Vec::with_capacity(MAX_TRANSFERS),
            chunk,
            acquired_at,
        })
    }
    fn publish(&self) -> Result<(), CliError> {
        backend(
            backend(self.conn.set_selection_owner(
                self.window,
                self.atoms.clipboard,
                self.acquired_at,
            ))?
            .check(),
        )?;
        if backend(backend(self.conn.get_selection_owner(self.atoms.clipboard))?.reply())?.owner
            != self.window
        {
            return Err(CliError::new(OTHER, "clipboard ownership was not acquired"));
        }
        Ok(())
    }
    fn finish(&self) -> Result<(), CliError> {
        self.conn
            .stream()
            .begin(Instant::now() + Duration::from_millis(250), true);
        backend(backend(self.conn.destroy_window(self.window))?.check())?;
        backend(self.conn.flush())
    }
    fn request(
        &mut self,
        request: SelectionRequestEvent,
        value: &[u8],
        end: Instant,
    ) -> Result<(), CliError> {
        let property = if request.property == NONE {
            request.target
        } else {
            request.property
        };
        let occupied = self
            .transfers
            .iter()
            .any(|t| t.window == request.requestor && t.property == property);
        let mut accepted = false;
        if request.response_type == SELECTION_REQUEST_EVENT
            && (request.time == CURRENT_TIME
                || request.time.wrapping_sub(self.acquired_at) < (1 << 31))
            && request.owner == self.window
            && request.selection == self.atoms.clipboard
            && !occupied
        {
            if request.target == self.atoms.targets {
                accepted = self
                    .conn
                    .change_property32(
                        PropMode::REPLACE,
                        request.requestor,
                        property,
                        AtomEnum::ATOM,
                        &self.atoms.supported(),
                    )
                    .ok()
                    .is_some_and(|c| c.check().is_ok());
            } else if request.target == self.atoms.hint {
                accepted = self
                    .conn
                    .change_property8(
                        PropMode::REPLACE,
                        request.requestor,
                        property,
                        request.target,
                        b"secret",
                    )
                    .ok()
                    .is_some_and(|c| c.check().is_ok());
            } else if [self.atoms.utf8, self.atoms.mime, self.atoms.plain].contains(&request.target)
            {
                if value.len() <= self.chunk {
                    accepted = self
                        .conn
                        .change_property8(
                            PropMode::REPLACE,
                            request.requestor,
                            property,
                            request.target,
                            value,
                        )
                        .ok()
                        .is_some_and(|c| c.check().is_ok());
                } else if self.transfers.len() < MAX_TRANSFERS {
                    let selected = self
                        .conn
                        .change_window_attributes(
                            request.requestor,
                            &ChangeWindowAttributesAux::new().event_mask(
                                EventMask::PROPERTY_CHANGE | EventMask::STRUCTURE_NOTIFY,
                            ),
                        )
                        .ok()
                        .is_some_and(|c| c.check().is_ok());
                    if selected {
                        accepted = self
                            .conn
                            .change_property32(
                                PropMode::REPLACE,
                                request.requestor,
                                property,
                                self.atoms.incr,
                                &[u32::try_from(value.len()).map_err(|_| {
                                    CliError::new(LIMIT, "clipboard value too large")
                                })?],
                            )
                            .ok()
                            .is_some_and(|c| c.check().is_ok());
                        if accepted {
                            self.transfers.push(Transfer {
                                window: request.requestor,
                                property,
                                target: request.target,
                                offset: 0,
                                deadline: (Instant::now() + Duration::from_secs(5)).min(end),
                            });
                        }
                    }
                }
            }
        }
        // Requestor disappearance is an ordinary rejected transfer, not a panic.
        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: request.time,
            requestor: request.requestor,
            selection: request.selection,
            target: request.target,
            property: if accepted { property } else { NONE },
        };
        if let Ok(cookie) =
            self.conn
                .send_event(false, request.requestor, EventMask::NO_EVENT, notify)
        {
            let _ = cookie.check();
        }
        backend(self.conn.flush())
    }
    fn advance(&mut self, event: PropertyNotifyEvent, value: &[u8], end: Instant) {
        if event.response_type != PROPERTY_NOTIFY_EVENT || event.state != Property::DELETE {
            return;
        }
        let Some(i) = self
            .transfers
            .iter()
            .position(|t| t.window == event.window && t.property == event.atom)
        else {
            return;
        };
        let transfer = &mut self.transfers[i];
        let next = value.len().min(transfer.offset + self.chunk);
        let done = transfer.offset == value.len();
        let sent = self
            .conn
            .change_property8(
                PropMode::REPLACE,
                transfer.window,
                transfer.property,
                transfer.target,
                &value[transfer.offset..next],
            )
            .ok()
            .is_some_and(|c| c.check().is_ok());
        if done || !sent {
            self.transfers.swap_remove(i);
        } else {
            transfer.offset = next;
            transfer.deadline = (Instant::now() + Duration::from_secs(5)).min(end);
        }
    }
    fn serve(&mut self, value: &[u8], options: ClipboardOptions) -> Result<(), CliError> {
        self.publish()?;
        let end = Instant::now() + options.timeout;
        let tty = rustix::termios::isatty(rustix::stdio::stderr());
        let mut last = None;
        loop {
            crate::signals::check()?;
            let now = Instant::now();
            if now >= end {
                break;
            }
            self.transfers.retain(|t| t.deadline > now);
            let left = end.saturating_duration_since(now).as_secs() + 1;
            if last != Some(left) && (tty || last.is_none()) {
                let mut out = Out::stderr();
                out.raw(&format!(
                    "{}Clipboard available: {left} s{}",
                    if tty { "\r" } else { "" },
                    if tty { " " } else { "\n" }
                ));
                out.flush()?;
                last = Some(left);
            }
            for _ in 0..64 {
                crate::signals::check()?;
                if Instant::now() >= end {
                    return Ok(());
                }
                self.conn
                    .stream()
                    .begin((Instant::now() + Duration::from_secs(5)).min(end), false);
                let Some(event) = backend(self.conn.poll_for_event())? else {
                    break;
                };
                match event {
                    Event::SelectionClear(e)
                        if e.selection == self.atoms.clipboard
                            && e.owner == self.window
                            && e.response_type == SELECTION_CLEAR_EVENT =>
                    {
                        return Ok(());
                    }
                    Event::SelectionRequest(e) => self.request(e, value, end)?,
                    Event::PropertyNotify(e) => self.advance(e, value, end),
                    Event::DestroyNotify(e) => self.transfers.retain(|t| t.window != e.window),
                    _ => {}
                }
            }
            backend(self.conn.flush())?;
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

pub(crate) fn hold(value: SecretBytes, options: ClipboardOptions) -> Result<(), CliError> {
    if value.len() > MAX_VALUE {
        return Err(CliError::new(LIMIT, "clipboard value exceeds model limit"));
    }
    if std::str::from_utf8(value.expose_secret()).is_err() {
        return Err(CliError::usage("clipboard value is not UTF-8 text"));
    }
    crate::signals::check()?;
    let mut owner = Owner::new()?;
    if qv_core::harden().memory.is_reduced() {
        crate::out::eprint(
            "qvault: warning: reduced protection: secret buffers could not all be locked in memory and may reach swap\n",
        );
    }
    let result = owner.serve(value.expose_secret(), options);
    let cleanup = owner.finish();
    drop(owner); // closes the dedicated connection even if cleanup failed
    drop(value);
    if rustix::termios::isatty(rustix::stdio::stderr()) {
        crate::out::eprint("\rClipboard session ended.              \n");
    }
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clipboard_rejects_invalid_text_and_size_before_backend() {
        let options = ClipboardOptions {
            timeout: Duration::from_secs(1),
        };
        let mut invalid = [0xff];
        assert_eq!(
            hold(SecretBytes::take_from(&mut invalid), options)
                .unwrap_err()
                .code,
            2
        );
        assert_eq!(invalid, [0]);
        assert_eq!(
            hold(SecretBytes::zeroed(MAX_VALUE + 1), options)
                .unwrap_err()
                .code,
            LIMIT
        );
    }
}
