// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unlocked screens: navigation, bounded protected inputs, typed actions,
//! confirmations, reveal and clipboard holds. Every action is checked here
//! against the current form epoch and screen before any core call; core
//! handles never leave Rust, and late worker results are dropped after a lock.
use crate::controller::{AppError, Controller, FormEpoch, Phase, State, Worker};
use qv_core::{
    AttachmentHandle, CancelToken, CoreError, EntryDraft, EntryHandle, FieldHandle, FieldId,
    FieldKind, Generated, GroupDraft, GroupHandle, ItemHandle, RecoveryPhrase, SecretBytes,
    Session, SettingsDraft,
};
use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Protected values are visible for at most this long after a reveal (0008 §4.3).
pub const REVEAL_FOR: Duration = Duration::from_secs(30);
/// Clipboard holds expire after this long when still owned (0008 §3).
pub const CLIPBOARD_FOR: Duration = Duration::from_secs(20);
/// Inactivity limit while a recovery phrase is displayed (plan 0031 decision 5).
pub const PHRASE_IDLE: Duration = Duration::from_secs(300);
/// Single-line input bound, in UTF-8 bytes (plan 0031 decision 4).
pub const LINE_MAX: usize = 1024;
/// Multi-line notes and protected value bound, below the 64 KiB IPC ingress
/// limit even with six-fold JSON control-character escaping.
pub const MULTI_MAX: usize = 8 * 1024;
/// Search query bound.
pub const QUERY_MAX: usize = 256;
/// Local path bound.
pub const PATH_MAX: usize = 4096;
/// Bounded back stack.
const BACK_MAX: usize = 32;

/// The unlocked screen authorized by Rust state.
#[derive(Clone, PartialEq)]
pub enum Screen {
    /// A group's children; `None` is the root.
    Browse(Option<GroupHandle>),
    /// Entries whose group is missing (0003 §4.1).
    Recovered,
    /// Search over non-protected data.
    Search,
    /// One entry.
    Entry(EntryHandle),
    /// The entry form.
    EditEntry,
    /// The group form.
    EditGroup,
    /// Choose a destination group for a move.
    Move(ItemHandle, Option<GroupHandle>),
    /// Trash.
    Trash,
    /// An entry's retained history.
    History(EntryHandle),
    /// One retained version, by full version ID.
    HistoryVersion(EntryHandle, String),
    /// All conflicted records.
    Conflicts,
    /// One conflicted record, by full record ID.
    ConflictRecord(String),
    /// An entry's attachments.
    Attachments(EntryHandle),
    /// Password generator.
    Generator,
    /// Local snapshots.
    Snapshots,
    /// Archive export and merge.
    Archives,
    /// LAN links, pairing and sync (0013).
    Devices,
    /// Settings.
    Settings(Pane),
    /// Choose a login for the bound autofill request.
    Autofill,
    /// The narrow layout's list of sections that have no bottom tab.
    More,
    /// Every entry of one type hint (lower-cased), as a list (plan 0040 R6).
    Kind(Zeroizing<String>),
}
/// Desktop keyboard shortcuts; each runs an action the screens already offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shortcut {
    /// Ctrl+F: open Search.
    Search,
    /// Ctrl+N: a new entry in the listed group.
    NewEntry,
    /// Ctrl+L: lock.
    Lock,
    /// Ctrl+S: save the open entry or group form.
    Save,
    /// Escape: cancel a pending question, else go back.
    Escape,
}
impl Shortcut {
    /// Map a key name (as the webview reports it) and the Ctrl state.
    pub fn from_key(key: &str, ctrl: bool) -> Option<Self> {
        match (key, ctrl) {
            ("Escape", false) => Some(Self::Escape),
            ("f" | "F", true) => Some(Self::Search),
            ("n" | "N", true) => Some(Self::NewEntry),
            ("l" | "L", true) => Some(Self::Lock),
            ("s" | "S", true) => Some(Self::Save),
            _ => None,
        }
    }
}
impl Screen {
    /// A list the three-pane layout shows beside a detail screen.
    pub fn is_list(&self) -> bool {
        matches!(
            self,
            Self::Browse(_) | Self::Search | Self::Recovered | Self::Kind(_)
        )
    }
    /// A vault screen shown in the detail pane, next to its list.
    pub fn is_vault_detail(&self) -> bool {
        matches!(
            self,
            Self::Entry(_)
                | Self::EditEntry
                | Self::EditGroup
                | Self::Move(..)
                | Self::History(_)
                | Self::HistoryVersion(..)
                | Self::Attachments(_)
        )
    }
    /// A form whose unsaved input a list selection must not discard.
    pub fn is_form(&self) -> bool {
        matches!(self, Self::EditEntry | Self::EditGroup | Self::Move(..))
    }
}
// Variant names only: no handle, ID or vault text reaches debug output.
impl std::fmt::Debug for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Browse(_) => "Browse",
            Self::Recovered => "Recovered",
            Self::Search => "Search",
            Self::Entry(_) => "Entry",
            Self::EditEntry => "EditEntry",
            Self::EditGroup => "EditGroup",
            Self::Move(..) => "Move",
            Self::Trash => "Trash",
            Self::History(_) => "History",
            Self::HistoryVersion(..) => "HistoryVersion",
            Self::Conflicts => "Conflicts",
            Self::ConflictRecord(_) => "ConflictRecord",
            Self::Attachments(_) => "Attachments",
            Self::Generator => "Generator",
            Self::Snapshots => "Snapshots",
            Self::Archives => "Archives",
            Self::Devices => "Devices",
            Self::Settings(_) => "Settings",
            Self::Autofill => "Autofill",
            Self::More => "More",
            Self::Kind(_) => "Kind",
        })
    }
}
/// Settings panes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    /// The settings home: grouped rows leading to the other panes.
    Overview,
    /// Vault name, description and retention.
    General,
    /// Change the master password.
    Password,
    /// Redisplay the recovery phrase after reauthentication.
    Phrase,
    /// Key rotation.
    Rotation,
    /// Integrity verification.
    Verify,
    /// Unverified header and vault overview.
    About,
}
/// One bounded input. Values are protected immediately; none is kept in a
/// frontend string cache.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WsField {
    /// Search query.
    Query,
    /// The command bar's query (plan 0040 R7); same bound as `Query`.
    Command,
    /// Entry title.
    Title,
    /// Entry type hint.
    TypeHint,
    /// Entry notes.
    Notes,
    /// A field name in the entry form.
    FieldName(u16),
    /// An unprotected field value in the entry form.
    FieldValue(u16),
    /// A protected replacement in the entry form; blank means unchanged.
    Replacement(u16),
    /// Name for a new field.
    NewFieldName,
    /// Group name.
    GroupName,
    /// Local path (Linux) or file name (Android private vaults).
    Path,
    /// Current master password (reauthentication).
    Password,
    /// New master password.
    NewPassword,
    /// New password confirmation.
    Repeat,
    /// A requested recovery word.
    Word(u8),
    /// Generator length (characters or PIN digits).
    GenLength,
    /// Generator word count.
    GenWords,
    /// Generator separator.
    GenSeparator,
    /// Generator excluded characters.
    GenExclude,
    /// Vault name.
    VaultName,
    /// Vault description.
    Description,
    /// History depth.
    HistoryDepth,
    /// Trash retention days.
    TrashDays,
    /// Attachment MIME type.
    AttachMime,
    /// Attachment name.
    AttachName,
    /// A typed confirmation word (key rotation).
    Confirmation,
    /// A typed LAN pairing code (protected: it carries the pairing secret).
    LanCode,
    /// The other device's address, `ip:port`.
    LanEndpoint,
    /// This device's name for the other device (1–64 bytes).
    LanLabel,
}
impl WsField {
    fn limit(self, multiline: bool) -> usize {
        match self {
            Self::Query | Self::Command => QUERY_MAX,
            Self::Path => PATH_MAX,
            Self::Notes | Self::Replacement(_) => MULTI_MAX,
            Self::FieldValue(_) if multiline => MULTI_MAX,
            _ => LINE_MAX,
        }
    }
}
/// What a reveal shows; at most one at a time.
#[derive(Clone, PartialEq)]
pub enum RevealKey {
    /// A current field.
    Field(FieldHandle),
    /// A field of a retained version.
    History(String, FieldId),
    /// A field of one conflicting version.
    Conflict(String, String, FieldId),
    /// A protected replacement typed or generated in the entry form.
    Replacement(u16),
    /// The generator's latest value.
    Generated,
    /// The current code of a TOTP field (never its seed).
    Totp(FieldHandle),
}
/// What a copy sends to the OS clipboard.
#[derive(Clone)]
pub enum CopyKey {
    /// A current field of a non-conflicted entry.
    Field(EntryHandle, FieldHandle),
    /// The current TOTP code of a field.
    Totp(EntryHandle, FieldHandle),
    /// The generator's latest value.
    Generated,
}
/// Generator mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenMode {
    /// Random characters.
    Characters,
    /// Passphrase.
    Words,
    /// PIN.
    Pin,
}
/// Generator toggles.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GenFlag {
    /// a–z.
    Lower,
    /// A–Z.
    Upper,
    /// 0–9.
    Digits,
    /// Punctuation.
    Symbols,
    /// Remove ambiguous characters.
    Ambiguous,
    /// Require every enabled character class.
    Each,
    /// Capitalize words.
    Capitalize,
    /// Append one digit.
    AppendDigit,
}
/// Typed, allowlisted unlocked actions.
#[derive(Clone)]
pub enum WsAction {
    /// Run the bounded search query.
    Search,
    /// Reveal one protected value for 30 s.
    Reveal(RevealKey),
    /// Hide the revealed value.
    Hide,
    /// Copy through Rust to the OS clipboard.
    Copy(CopyKey),
    /// Start a new entry in a group.
    NewEntry(GroupHandle),
    /// Edit an existing entry.
    EditEntry(EntryHandle),
    /// Add a field to the entry form.
    AddField(FieldKind),
    /// Remove a form field.
    RemoveField(u16),
    /// Toggle a form field's protection.
    ToggleProtect(u16),
    /// Generate a protected replacement with the vault defaults.
    GenerateInto(u16),
    /// Save the entry form.
    SaveEntry,
    /// Start a new group under a parent.
    NewGroup(GroupHandle),
    /// Rename a group.
    RenameGroup(GroupHandle),
    /// Save the group form.
    SaveGroup,
    /// Move an item to a group.
    MoveTo(ItemHandle, GroupHandle),
    /// Move an item to the trash.
    Delete(ItemHandle),
    /// Restore an item from the trash.
    Restore(ItemHandle),
    /// Permanently delete all non-conflicted trash.
    EmptyTrash,
    /// Permanently delete trash past its retention.
    PurgeExpired,
    /// Restore a retained version as a new edit.
    RestoreHistory(EntryHandle, String, bool),
    /// Suppress and purge an entry's history.
    PurgeHistory(EntryHandle),
    /// Choose a complete version for a conflicted record.
    Resolve(String, String),
    /// Restore a snapshot into a new vault file (reauthenticates).
    RestoreSnapshot(String),
    /// Export an archive; `true` adds the password slot.
    ExportArchive(bool),
    /// Merge an archive from the path input.
    MergeArchive,
    /// Add an attachment from the path input.
    AddAttachment(EntryHandle),
    /// Save an attachment's plaintext to the path input.
    SaveAttachment(AttachmentHandle),
    /// Permanently remove an attachment.
    RemoveAttachment(AttachmentHandle),
    /// Generator mode.
    GenMode(GenMode),
    /// Generator toggle.
    GenToggle(GenFlag),
    /// Generate with the current generator settings.
    Generate,
    /// Suggest a six-word master password without exposing it to clipboard IPC.
    SuggestPassword,
    /// Store the generator settings as the vault defaults.
    SaveGeneratorDefaults,
    /// Save general settings.
    SaveSettings,
    /// Change the master password.
    ChangePassword,
    /// Enroll a validated device-local hardware wrapping policy.
    EnrollQuick(qv_core::platform::QuickPolicy),
    /// Destroy the quick-unlock handle and process policy.
    DisableQuick,
    /// Fill the bound autofill request from this chosen entry head.
    AutofillFill(qv_core::autofill::CandidateKey),
    /// Abandon the bound autofill request.
    AutofillCancel,
    /// Link the requesting app's verified identity to this entry.
    AutofillLink(EntryHandle),
    /// Open the OS autofill-service settings.
    OpenAutofillSettings,
    /// Delete snapshots taken before a password change.
    DeleteOldSnapshots,
    /// Show the recovery phrase after reauthentication.
    ShowPhrase,
    /// Confirm requested recovery words for the displayed phrase.
    ConfirmWords,
    /// Hide the displayed recovery phrase.
    HidePhrase,
    /// Start key rotation (password inputs, typed confirmation). The prepared
    /// rotation continues in the controller's rotation phase.
    BeginRotation,
    /// Verify integrity.
    Verify,
    /// Open a pairing window (0013 §4).
    LanPair,
    /// Open a receive window (0013 §8).
    LanReceive,
    /// Sync with the link of this ID against the typed endpoint.
    LanSync(String),
    /// Join a pairing window with this vault (link mode).
    LanLink,
    /// Remove the link of this ID (after confirmation).
    LanRemove(String),
    /// Answer the pending confirmation.
    Answer(bool),
    /// Dismiss the current notice or report.
    Dismiss,
}
/// Confirmation kinds, each with fixed text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmKind {
    /// Delete a non-empty group with its contents.
    DeleteRecursive,
    /// Empty the trash.
    EmptyTrash,
    /// Purge expired trash, with a clock warning when needed.
    PurgeExpired(bool),
    /// Purge an entry's history.
    PurgeHistory,
    /// Remove an attachment.
    RemoveAttachment,
    /// Write attachment plaintext to the chosen destination.
    SaveAttachment,
    /// Include the password slot in an exported archive.
    SelfContained,
    /// Create a complete-version resolution; `true` for permanent deletion.
    Resolve(bool),
    /// Restore over conflicting heads.
    RestoreConflicts,
    /// The mandatory recovery snapshot needs this many bytes over budget.
    OverBudget(u64),
    /// Delete snapshots taken before the password change.
    OldSnapshots(usize),
    /// Accept a weak new master password.
    WeakPassword,
    /// Device PIN/pattern becomes a vault credential.
    ReducedQuick,
    /// Link an OS-verified app identity to an entry.
    LinkApp,
    /// Remove a LAN link.
    RemoveLink,
}
struct Pending {
    kind: ConfirmKind,
    action: WsAction,
    over_budget: bool,
}
/// The entry form wraps an owned core draft; protected values stay in it or
/// in protected replacements and are never prefilled into inputs.
pub(crate) struct EntryForm {
    pub(crate) draft: EntryDraft,
    pub(crate) new: bool,
    pub(crate) replacements: BTreeMap<u16, SecretBytes>,
    pub(crate) generated: Vec<u16>,
    pub(crate) too_large: Vec<u16>,
    pub(crate) notes_too_large: bool,
}
/// The group form.
pub(crate) struct GroupForm {
    pub(crate) draft: GroupDraft,
    pub(crate) new: bool,
}
/// Generator form state; settings are revalidated by core at use.
#[derive(Clone)]
pub(crate) struct GenForm {
    pub(crate) mode: GenMode,
    pub(crate) length: u32,
    pub(crate) words: u32,
    pub(crate) pin: u32,
    pub(crate) flags: [bool; 8],
    pub(crate) separator: char,
    pub(crate) exclude: zeroize::Zeroizing<String>,
}
/// A recovery phrase redisplayed after reauthentication (0002 §4.2).
pub(crate) enum PhraseView {
    Redisplay {
        phrase: RecoveryPhrase,
        positions: [usize; 3],
        confirmed: bool,
    },
}
/// Fixed-label results; no secret, path or record content.
#[derive(Clone, Debug, PartialEq)]
pub enum Report {
    /// Archive merge outcome.
    Merge {
        /// A new acceptance committed.
        accepted: bool,
        /// Remaining conflicts.
        conflicts: usize,
        /// Completion failed after durable acceptance.
        incomplete: bool,
    },
    /// Archive export outcome.
    Export {
        /// Published archive ID.
        id: String,
        /// Includes a password slot.
        self_contained: bool,
        /// Durability unconfirmed after publication.
        incomplete: bool,
    },
    /// Conflict resolution outcome.
    Resolved {
        /// Remaining conflicts.
        conflicts: usize,
        /// Completion failed after durable publication.
        incomplete: bool,
    },
    /// Integrity verification.
    Verify {
        /// Every check passed and the anchor is verified or advanced.
        ok: bool,
        /// Fixed anchor label.
        anchor: &'static str,
        /// Objects re-hashed.
        objects: u64,
        /// Bytes re-hashed.
        bytes: u64,
        /// Records checked.
        records: u64,
        /// Fixed note labels.
        notes: Vec<&'static str>,
    },
    /// Trash purge outcome.
    Purged {
        /// Items deleted.
        purged: usize,
        /// Conflicted items kept.
        kept: usize,
    },
}
/// Clipboard hold slot; dropping the workspace cancels it.
struct Clip {
    cancel: CancelToken,
    remaining: Arc<AtomicU64>,
}
/// State of the unlocked screens; dropped on every lock.
pub struct Workspace {
    pub(crate) screen: Screen,
    back: Vec<Screen>,
    pub(crate) inputs: BTreeMap<WsField, SecretBytes>,
    /// Scanned address-only hints, retained only for this form.
    pub(crate) lan_endpoints: Vec<std::net::SocketAddr>,
    pub(crate) entry_form: Option<EntryForm>,
    pub(crate) group_form: Option<GroupForm>,
    pub(crate) settings: Option<SettingsDraft>,
    pub(crate) generator: GenForm,
    pub(crate) generated: Option<(Generated, Instant)>,
    reveal: Option<(RevealKey, SecretBytes, Instant)>,
    pending: Option<Pending>,
    pub(crate) notice: Option<&'static str>,
    pub(crate) error: Option<AppError>,
    pub(crate) report: Option<Report>,
    /// The item just moved to the trash, until the next navigation (Undo).
    pub(crate) undo: Option<qv_core::ItemHandle>,
    pub(crate) phrase: Option<PhraseView>,
    pub(crate) old_snapshots: Vec<String>,
    pub(crate) searched: bool,
    pub(crate) weak_until: Option<Instant>,
    pub(crate) weak_accepted: bool,
    pub(crate) fair_warning: bool,
    clip: Option<Clip>,
}
impl Drop for Workspace {
    fn drop(&mut self) {
        if let Some(clip) = &self.clip {
            clip.cancel.cancel();
        }
    }
}
/// Renderer-visible time-dependent state, compared to trigger a refresh.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Live {
    /// A reveal is currently visible.
    pub reveal: bool,
    /// Seconds before the visible reveal hides; 0 when none.
    pub reveal_left: u64,
    /// Seconds before the clipboard hold ends; 0 when none.
    pub clipboard: u64,
    /// The generated value is still displayed.
    pub generated: bool,
    /// Rust-enforced delay before weak-master-password consent.
    pub weak_seconds: u64,
}
/// Expire time-limited values and report the visible state.
pub(crate) fn live(s: &mut State) -> (u64, Live) {
    let mut changed = false;
    let live = match s.workspace.as_mut() {
        Some(ws) => {
            if ws
                .reveal
                .as_ref()
                .is_some_and(|r| r.2.elapsed() >= REVEAL_FOR)
            {
                ws.reveal = None;
                changed = true;
            }
            if ws
                .generated
                .as_ref()
                .is_some_and(|g| g.1.elapsed() >= REVEAL_FOR)
            {
                ws.generated = None;
                changed = true;
            }
            let clipboard = ws
                .clip
                .as_ref()
                .map_or(0, |c| c.remaining.load(Ordering::SeqCst));
            Live {
                reveal: ws.reveal.is_some(),
                reveal_left: ws.reveal.as_ref().map_or(0, |r| {
                    let left = REVEAL_FOR.saturating_sub(r.2.elapsed());
                    left.as_secs() + u64::from(left.subsec_nanos() > 0)
                }),
                clipboard,
                generated: ws.generated.is_some(),
                weak_seconds: ws.weak_until.map_or(0, |until| {
                    let left = until.saturating_duration_since(Instant::now());
                    left.as_secs() + u64::from(left.subsec_nanos() > 0)
                }),
            }
        }
        None => Live::default(),
    };
    if changed {
        s.revision = s.revision.wrapping_add(1);
    }
    (s.revision, live)
}
impl Workspace {
    pub(crate) fn new(recovered_with_phrase: bool) -> Self {
        let mut ws = Self {
            screen: Screen::Browse(None),
            back: Vec::new(),
            inputs: BTreeMap::new(),
            lan_endpoints: Vec::new(),
            entry_form: None,
            group_form: None,
            settings: None,
            generator: GenForm {
                mode: GenMode::Characters,
                length: 24,
                words: 6,
                pin: 6,
                flags: [true, true, true, true, false, false, false, true],
                separator: '.',
                exclude: zeroize::Zeroizing::new(String::new()),
            },
            generated: None,
            reveal: None,
            pending: None,
            notice: None,
            error: None,
            report: None,
            undo: None,
            phrase: None,
            old_snapshots: Vec::new(),
            searched: false,
            weak_until: None,
            weak_accepted: false,
            fair_warning: false,
            clip: None,
        };
        if recovered_with_phrase {
            ws.screen = Screen::Settings(Pane::Password);
            ws.notice = Some(
                "Opened with the recovery phrase. You can set a new master password now, or skip.",
            );
        }
        ws
    }
    /// Whether a recovery phrase is on screen (longer inactivity limit).
    pub(crate) fn shows_phrase(&self) -> bool {
        self.phrase.is_some()
    }
    fn clear_transient(&mut self) {
        self.inputs.clear();
        self.lan_endpoints.clear();
        self.generated = None;
        self.weak_until = None;
        self.weak_accepted = false;
        self.fair_warning = false;
        self.entry_form = None;
        self.group_form = None;
        self.settings = None;
        self.reveal = None;
        self.pending = None;
        self.phrase = None;
        self.report = None;
        self.error = None;
        self.searched = false;
        self.undo = None;
    }
    pub(crate) fn go(&mut self, to: Screen) {
        if self.screen != to {
            let from = std::mem::replace(&mut self.screen, to);
            if self.back.len() == BACK_MAX {
                self.back.remove(0);
            }
            self.back.push(from);
        }
        self.clear_transient();
        self.notice = None;
    }
    /// Replace the current vault detail screen with a sibling, so Back still
    /// returns to the list. Anywhere else this is an ordinary navigation.
    pub(crate) fn select(&mut self, to: Screen) {
        if self.screen.is_vault_detail() && !self.screen.is_form() {
            self.screen = to;
            self.clear_transient();
            self.notice = None;
        } else {
            self.go(to);
        }
    }
    /// The list shown beside the current screen: the screen itself when it is
    /// a list, else the nearest list in the back stack, else the root group.
    pub(crate) fn list_context(&self) -> Screen {
        std::iter::once(&self.screen)
            .chain(self.back.iter().rev())
            .find(|s| s.is_list())
            .cloned()
            .unwrap_or(Screen::Browse(None))
    }
    pub(crate) fn input(&self, field: WsField) -> &[u8] {
        self.inputs
            .get(&field)
            .map_or(&[][..], SecretBytes::expose_secret)
    }
    pub(crate) fn text(&self, field: WsField) -> Result<&str, AppError> {
        std::str::from_utf8(self.input(field)).map_err(|_| AppError::InvalidInput)
    }
    /// The revealed value for a key, while unexpired.
    pub(crate) fn revealed(&self, key: &RevealKey) -> Option<&SecretBytes> {
        self.reveal
            .as_ref()
            .filter(|r| &r.0 == key && r.2.elapsed() < REVEAL_FOR)
            .map(|r| &r.1)
    }
    pub(crate) fn pending(&self) -> Option<ConfirmKind> {
        self.pending.as_ref().map(|p| p.kind)
    }
    /// Ask for a typed confirmation before re-dispatching `action`.
    pub(crate) fn set_pending(&mut self, kind: ConfirmKind, action: WsAction, over_budget: bool) {
        self.pending = Some(Pending {
            kind,
            action,
            over_budget,
        });
    }
}
/// A worker's effect on controller state, applied only within the same lock
/// generation (and so never to a later session).
pub(crate) type Apply = Box<dyn FnOnce(&mut State) + Send>;
/// Apply an effect to the workspace only.
pub(crate) fn on_ws(f: impl FnOnce(&mut Workspace) + Send + 'static) -> Apply {
    Box::new(move |s: &mut State| {
        if let Some(ws) = s.workspace.as_mut() {
            #[cfg(target_os = "android")]
            let previous = ws.screen.clone();
            f(ws);
            #[cfg(target_os = "android")]
            if previous != ws.screen {
                crate::android::forget_pick();
            }
        }
    })
}
/// Copy bounded bytes into a protected container.
pub(crate) fn protect(bytes: &[u8]) -> Result<SecretBytes, AppError> {
    SecretBytes::try_init(bytes.len(), |out| {
        out.copy_from_slice(bytes);
        Ok::<(), AppError>(())
    })
}
impl Controller {
    /// Current unlocked screen, if the epoch is current and a workspace exists.
    pub fn screen(&self, epoch: FormEpoch) -> Option<Screen> {
        let s = self.state();
        (s.epoch == epoch.0)
            .then(|| s.workspace.as_ref().map(|w| w.screen.clone()))
            .flatten()
    }
    /// Run `f` on the unlocked workspace for the current epoch.
    pub(crate) fn with_ws<T>(
        &self,
        epoch: FormEpoch,
        f: impl FnOnce(&mut Workspace, &Arc<Session>) -> T,
    ) -> Option<T> {
        let mut s = self.state();
        if s.epoch != epoch.0 || s.phase != Phase::Unlocked {
            return None;
        }
        let session = s.session.clone()?;
        s.active = Instant::now();
        #[cfg(target_os = "android")]
        let previous = s.workspace.as_ref()?.screen.clone();
        let out = f(s.workspace.as_mut()?, &session);
        #[cfg(target_os = "android")]
        if s.workspace.as_ref()?.screen != previous {
            crate::android::forget_pick();
        }
        s.revision = s.revision.wrapping_add(1);
        Some(out)
    }
    /// Read-only access for rendering. The state lock is released before the
    /// core call; nothing is read while a worker owns the session.
    pub(crate) fn read<T>(
        &self,
        epoch: FormEpoch,
        f: impl FnOnce(&Session) -> Result<T, CoreError>,
    ) -> Option<Result<T, AppError>> {
        let session = {
            let s = self.state();
            if s.epoch != epoch.0
                || s.phase != Phase::Unlocked
                || self.0.working.load(Ordering::SeqCst)
            {
                return None;
            }
            s.session.clone()?
        };
        Some(f(&session).map_err(AppError::from))
    }
    /// Advance the revision for an outside change screens must show (a
    /// system file picker finishing).
    #[cfg_attr(not(feature = "desktop"), allow(dead_code))]
    pub(crate) fn touch(&self) {
        let mut s = self.state();
        s.revision = s.revision.wrapping_add(1);
    }
    /// Read the workspace without changing the revision.
    pub(crate) fn peek<T>(&self, epoch: FormEpoch, f: impl FnOnce(&Workspace) -> T) -> Option<T> {
        let s = self.state();
        if s.epoch != epoch.0 || s.phase != Phase::Unlocked {
            return None;
        }
        s.workspace.as_ref().map(f)
    }
    /// Navigate; forms, reveals and pending confirmations are discarded and the
    /// form epoch advances so late input for the old screen is ignored.
    pub fn navigate(&self, epoch: FormEpoch, to: Screen) {
        self.navigate_with(epoch, to, false);
    }
    /// Open a sibling from the list pane (see [`Workspace::select`]).
    pub fn select(&self, epoch: FormEpoch, to: Screen) {
        self.navigate_with(epoch, to, true);
    }
    /// The list shown beside the current screen (see [`Workspace::list_context`]).
    pub fn list_context(&self, epoch: FormEpoch) -> Option<Screen> {
        self.peek(epoch, Workspace::list_context)
    }
    fn navigate_with(&self, epoch: FormEpoch, to: Screen, replace: bool) {
        let mut s = self.state();
        if s.epoch != epoch.0 || s.phase != Phase::Unlocked || self.0.working.load(Ordering::SeqCst)
        {
            return;
        }
        // Document picks are screen-scoped, like the Linux path field.
        #[cfg(target_os = "android")]
        crate::android::forget_pick();
        let Some(session) = s.session.clone() else {
            return;
        };
        let Some(ws) = s.workspace.as_mut() else {
            return;
        };
        if matches!(to, Screen::EditEntry | Screen::EditGroup) {
            return;
        }
        if replace {
            ws.select(to);
        } else {
            ws.go(to);
        }
        crate::ops::on_enter(ws, &session);
        s.epoch = s.epoch.wrapping_add(1);
        s.active = Instant::now();
        s.revision = s.revision.wrapping_add(1);
    }
    /// Return to the previous screen.
    pub fn back(&self, epoch: FormEpoch) {
        let mut s = self.state();
        if s.epoch != epoch.0 || s.phase != Phase::Unlocked || self.0.working.load(Ordering::SeqCst)
        {
            return;
        }
        let Some(ws) = s.workspace.as_mut() else {
            return;
        };
        #[cfg(target_os = "android")]
        crate::android::forget_pick();
        let to = ws.back.pop().unwrap_or(Screen::Browse(None));
        ws.screen = to;
        ws.clear_transient();
        ws.notice = None;
        if let Some(session) = s.session.clone()
            && let Some(ws) = s.workspace.as_mut()
        {
            crate::ops::on_enter(ws, &session);
        }
        s.epoch = s.epoch.wrapping_add(1);
        s.active = Instant::now();
        s.revision = s.revision.wrapping_add(1);
    }
    /// Run a desktop shortcut for an existing action on the current unlocked
    /// screen. Lock always applies; everything else is ignored while a task
    /// runs. Escape never confirms: it cancels a pending question first, then
    /// goes back. Returns whether the key was used.
    pub fn shortcut(&self, epoch: FormEpoch, key: Shortcut) -> bool {
        let Some(screen) = self.screen(epoch) else {
            return false;
        };
        if key == Shortcut::Lock {
            self.lock();
            return true;
        }
        if self.0.working.load(Ordering::SeqCst) {
            return false;
        }
        match key {
            Shortcut::Lock => false,
            Shortcut::Search => {
                self.navigate(epoch, Screen::Search);
                true
            }
            Shortcut::NewEntry => {
                let group = match self.list_context(epoch) {
                    Some(Screen::Browse(Some(g))) => Some(g),
                    _ => self.read(epoch, |s| s.root()).and_then(Result::ok),
                };
                let Some(group) = group else {
                    return false;
                };
                self.act(epoch, WsAction::NewEntry(group));
                true
            }
            Shortcut::Save => match screen {
                Screen::EditEntry => {
                    self.act(epoch, WsAction::SaveEntry);
                    true
                }
                Screen::EditGroup => {
                    self.act(epoch, WsAction::SaveGroup);
                    true
                }
                _ => false,
            },
            Shortcut::Escape => {
                if self.pending(epoch).is_some() {
                    self.act(epoch, WsAction::Answer(false));
                    true
                } else if screen != Screen::Browse(None) {
                    self.back(epoch);
                    true
                } else {
                    false
                }
            }
        }
    }
    /// Transfer one bounded framework value into protected state, clearing the
    /// framework string even when the input is stale or refused.
    pub fn ws_input(&self, epoch: FormEpoch, field: WsField, value: &mut String) {
        let busy = self.0.working.load(Ordering::SeqCst);
        let mut s = self.state();
        let current = s.epoch == epoch.0 && s.phase == Phase::Unlocked && !busy;
        if current && let Some(ws) = s.workspace.as_mut() {
            if matches!(field, WsField::LanEndpoint | WsField::LanCode) {
                ws.lan_endpoints.clear();
            }
            if matches!(
                field,
                WsField::NewPassword | WsField::Repeat | WsField::Confirmation
            ) {
                ws.weak_until = None;
                ws.weak_accepted = false;
                ws.fair_warning = false;
                if ws.pending() == Some(ConfirmKind::WeakPassword) {
                    ws.pending = None;
                }
            }
            let multiline = match field {
                WsField::FieldValue(i) => ws.entry_form.as_ref().is_some_and(|f| {
                    f.draft
                        .entry()
                        .fields
                        .get(usize::from(i))
                        .is_some_and(|x| x.kind == FieldKind::Multiline)
                }),
                _ => false,
            };
            let result = if value.len() > field.limit(multiline) || value.contains('\0') {
                Err(AppError::InvalidInput)
            } else {
                apply_input(ws, field, value)
            };
            if matches!(field, WsField::NewPassword) {
                ws.fair_warning =
                    qv_core::MasterPassword::from_utf8(ws.input(field)).is_ok_and(|p| {
                        qv_core::password_strength(&p).verdict == qv_core::PasswordVerdict::Warn
                    });
            }
            match result {
                Ok(()) => ws.error = None,
                Err(e) => {
                    ws.inputs.remove(&field);
                    ws.error = Some(e);
                }
            }
            s.active = Instant::now();
            s.revision = s.revision.wrapping_add(1);
        }
        drop(s);
        value.zeroize();
        value.clear();
    }
    /// The protected value currently revealed for `key`, copied for display.
    pub fn revealed(&self, epoch: FormEpoch, key: &RevealKey) -> Option<SecretBytes> {
        self.peek(epoch, |ws| {
            ws.revealed(key)
                .and_then(|v| protect(v.expose_secret()).ok())
        })
        .flatten()
    }
    /// The generated value while displayed (30 s).
    pub fn generated(&self, epoch: FormEpoch) -> Option<(SecretBytes, f64)> {
        self.peek(epoch, |ws| {
            ws.generated.as_ref().and_then(|(g, at)| {
                (at.elapsed() < REVEAL_FOR)
                    .then(|| {
                        protect(g.expose_secret().as_bytes())
                            .ok()
                            .map(|v| (v, g.estimate().bits))
                    })
                    .flatten()
            })
        })
        .flatten()
    }
    /// Dispatch a typed unlocked action; refusals are shown on the screen.
    pub fn act(&self, epoch: FormEpoch, action: WsAction) {
        if let Err(error) = self.dispatch(epoch, action, false, false) {
            self.with_ws(epoch, |ws, _| ws.error = Some(error));
        }
    }
    pub(crate) fn dispatch(
        &self,
        epoch: FormEpoch,
        action: WsAction,
        confirmed: bool,
        over_budget: bool,
    ) -> Result<(), AppError> {
        if self.0.working.load(Ordering::SeqCst) {
            return Err(AppError::Busy);
        }
        if let WsAction::Answer(yes) = action {
            let pending = self
                .with_ws(epoch, |ws, _| {
                    if yes
                        && ws.pending() == Some(ConfirmKind::WeakPassword)
                        && ws.weak_until.is_none_or(|until| Instant::now() < until)
                    {
                        return None;
                    }
                    if !yes {
                        ws.weak_until = None;
                    }
                    if yes && ws.pending() == Some(ConfirmKind::WeakPassword) {
                        ws.weak_accepted = true;
                    }
                    ws.pending.take()
                })
                .ok_or(AppError::InvalidInput)?;
            let Some(p) = pending else {
                return Err(AppError::InvalidInput);
            };
            if !yes {
                return Ok(());
            }
            let over = p.over_budget || matches!(p.kind, ConfirmKind::OverBudget(_));
            return self.dispatch(epoch, p.action, true, over);
        }
        if !confirmed && let Some(kind) = self.needs_confirmation(epoch, &action)? {
            self.with_ws(epoch, |ws, _| {
                ws.pending = Some(Pending {
                    kind,
                    action,
                    over_budget,
                })
            })
            .ok_or(AppError::InvalidInput)?;
            return Ok(());
        }
        crate::ops::run(self, epoch, action, over_budget)
    }
    fn needs_confirmation(
        &self,
        epoch: FormEpoch,
        action: &WsAction,
    ) -> Result<Option<ConfirmKind>, AppError> {
        Ok(match action {
            WsAction::Delete(ItemHandle::Group(g)) => {
                let g = *g;
                let nonempty = self
                    .read(epoch, |s| {
                        let l = s.list(g)?;
                        Ok(!l.groups.is_empty() || !l.entries.is_empty())
                    })
                    .ok_or(AppError::InvalidInput)??;
                nonempty.then_some(ConfirmKind::DeleteRecursive)
            }
            WsAction::EnrollQuick(qv_core::platform::QuickPolicy::DeviceCredential) => {
                Some(ConfirmKind::ReducedQuick)
            }
            WsAction::AutofillLink(_) => Some(ConfirmKind::LinkApp),
            WsAction::LanRemove(_) => Some(ConfirmKind::RemoveLink),
            WsAction::EmptyTrash => Some(ConfirmKind::EmptyTrash),
            WsAction::PurgeExpired => {
                let anomaly = self
                    .read(epoch, |s| Ok(s.expired_trash()?.clock_anomaly))
                    .ok_or(AppError::InvalidInput)??;
                Some(ConfirmKind::PurgeExpired(anomaly))
            }
            WsAction::PurgeHistory(_) => Some(ConfirmKind::PurgeHistory),
            WsAction::RemoveAttachment(_) => Some(ConfirmKind::RemoveAttachment),
            WsAction::SaveAttachment(_) => Some(ConfirmKind::SaveAttachment),
            WsAction::ExportArchive(true) => Some(ConfirmKind::SelfContained),
            WsAction::Resolve(record, version) => {
                let final_delete = self
                    .read(epoch, |s| crate::ops::is_final_deletion(s, record, version))
                    .ok_or(AppError::InvalidInput)??;
                Some(ConfirmKind::Resolve(final_delete))
            }
            WsAction::RestoreHistory(_, _, true) => Some(ConfirmKind::RestoreConflicts),
            WsAction::DeleteOldSnapshots => {
                let n = self
                    .peek(epoch, |ws| ws.old_snapshots.len())
                    .ok_or(AppError::InvalidInput)?;
                Some(ConfirmKind::OldSnapshots(n))
            }
            _ => None,
        })
    }
    /// Run one vault operation on the single worker. Lock cancels it; a late
    /// result from an older lock generation is dropped, never applied.
    pub(crate) fn run_op<F>(
        &self,
        epoch: FormEpoch,
        retry: Option<WsAction>,
        op: F,
    ) -> Result<(), AppError>
    where
        F: FnOnce(&Session, &CancelToken, &Controller) -> Result<Apply, AppError> + Send + 'static,
    {
        let mut s = self.state();
        if s.epoch != epoch.0 || s.phase != Phase::Unlocked {
            return Err(AppError::InvalidInput);
        }
        if self.0.working.swap(true, Ordering::SeqCst) {
            return Err(AppError::Busy);
        }
        let worker = Worker(self.0.clone());
        let Some(session) = s.session.clone() else {
            return Err(AppError::InvalidInput);
        };
        let token = s.cancel.clone();
        let generation = s.lock_gen;
        s.op_running = true;
        s.active = Instant::now();
        s.revision = s.revision.wrapping_add(1);
        if let Some(ws) = s.workspace.as_mut() {
            ws.error = None;
            ws.notice = None;
            ws.report = None;
        }
        drop(s);
        let controller = self.clone();
        std::thread::Builder::new()
            .name("qv-app-op".into())
            .spawn(move || {
                let result = op(&session, &token, &controller);
                let mut s = controller.state();
                if s.lock_gen != generation || token.is_cancelled() {
                    drop(result);
                    drop(s);
                    drop(worker);
                    return;
                }
                s.op_running = false;
                s.revision = s.revision.wrapping_add(1);
                s.active = Instant::now();
                // Release the permit before applying so the next action may start.
                drop(worker);
                if let Ok(apply) = result {
                    apply(&mut s);
                    return;
                }
                if let Some(ws) = s.workspace.as_mut() {
                    match result {
                        Ok(_) => {}
                        Err(AppError::Core(CoreError::SnapshotOverBudget { needed }))
                            if retry.is_some() =>
                        {
                            if let Some(action) = retry {
                                ws.pending = Some(Pending {
                                    kind: ConfirmKind::OverBudget(needed),
                                    action,
                                    over_budget: true,
                                });
                            }
                        }
                        Err(e) => ws.error = Some(e),
                    }
                }
            })
            .map_err(|_| {
                self.0.working.store(false, Ordering::SeqCst);
                self.state().op_running = false;
                AppError::Unavailable
            })?;
        Ok(())
    }
    /// Store a revealed value for 30 s, replacing any other.
    pub(crate) fn set_reveal(ws: &mut Workspace, key: RevealKey, value: SecretBytes) {
        ws.reveal = Some((key, value, Instant::now()));
    }
    pub(crate) fn hide(ws: &mut Workspace) {
        ws.reveal = None;
    }
    /// Start a clipboard hold, replacing (and cancelling) any previous one.
    /// The value never reaches the progress callback.
    pub(crate) fn start_clip(
        &self,
        epoch: FormEpoch,
        value: SecretBytes,
        session: Option<Arc<Session>>,
    ) -> Result<(), AppError> {
        if !self.0.services.status().clipboard {
            return Err(AppError::ClipboardUnavailable);
        }
        let cancel = CancelToken::new();
        let remaining = Arc::new(AtomicU64::new(CLIPBOARD_FOR.as_secs()));
        let generation = {
            let mut s = self.state();
            if s.epoch != epoch.0 || s.phase != Phase::Unlocked {
                return Err(AppError::InvalidInput);
            }
            let generation = s.lock_gen;
            let ws = s.workspace.as_mut().ok_or(AppError::InvalidInput)?;
            if let Some(old) = ws.clip.replace(Clip {
                cancel: cancel.clone(),
                remaining: remaining.clone(),
            }) {
                old.cancel.cancel();
            }
            ws.notice = Some("Copied. The clipboard clears when the countdown ends, if unchanged.");
            s.revision = s.revision.wrapping_add(1);
            generation
        };
        let services = self.0.services.clone();
        let controller = self.clone();
        let mine = cancel.clone();
        std::thread::Builder::new()
            .name("qv-app-clipboard".into())
            .spawn(move || {
                let counter = remaining.clone();
                let mut progress = move |left: u64| {
                    counter.store(left, Ordering::SeqCst);
                    Ok(())
                };
                let result = match session {
                    Some(session) => session
                        .hold_clipboard(
                            services.clipboard(),
                            value,
                            CLIPBOARD_FOR,
                            Some(&mine),
                            &mut progress,
                        )
                        .map_err(AppError::from),
                    None => {
                        let token = mine.clone();
                        services
                            .clipboard()
                            .hold(
                                value,
                                CLIPBOARD_FOR,
                                Arc::new(move || token.is_cancelled()),
                                &mut progress,
                            )
                            .map_err(|_| AppError::ClipboardUnavailable)
                    }
                };
                let mut s = controller.state();
                if s.lock_gen != generation {
                    return;
                }
                if let Some(ws) = s.workspace.as_mut()
                    && ws
                        .clip
                        .as_ref()
                        .is_some_and(|c| Arc::ptr_eq(&c.remaining, &remaining))
                {
                    ws.clip = None;
                    if result.is_err() && !mine.is_cancelled() {
                        ws.error = Some(AppError::ClipboardUnavailable);
                    } else if ws.notice.is_some_and(|n| n.starts_with("Copied")) {
                        ws.notice = None;
                    }
                    s.revision = s.revision.wrapping_add(1);
                }
            })
            .map_err(|_| AppError::Unavailable)?;
        Ok(())
    }
    /// The pending confirmation, if any.
    pub fn pending(&self, epoch: FormEpoch) -> Option<ConfirmKind> {
        self.peek(epoch, Workspace::pending).flatten()
    }
}
/// Apply one bounded input. Unprotected entry values update the draft;
/// protected replacements stay separate until save; blank means unchanged.
fn apply_input(ws: &mut Workspace, field: WsField, value: &str) -> Result<(), AppError> {
    let text = |v: &str| qv_core::Text::new(v).map_err(|_| AppError::InvalidInput);
    match field {
        WsField::Title
        | WsField::TypeHint
        | WsField::Notes
        | WsField::FieldName(_)
        | WsField::FieldValue(_) => {
            let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
            let entry = form.draft.entry_mut();
            match field {
                WsField::Title => entry.title = text(value)?,
                WsField::TypeHint => entry.type_hint = text(value)?,
                WsField::Notes => {
                    if form.notes_too_large {
                        return Err(AppError::TooLargeForApp);
                    }
                    entry.notes = (!value.is_empty()).then(|| text(value)).transpose()?;
                }
                WsField::FieldName(i) => {
                    let f = entry
                        .fields
                        .get_mut(usize::from(i))
                        .ok_or(AppError::InvalidInput)?;
                    if value.is_empty() {
                        return Err(AppError::InvalidInput);
                    }
                    f.name = text(value)?;
                }
                WsField::FieldValue(i) => {
                    if form.too_large.contains(&i) {
                        return Err(AppError::TooLargeForApp);
                    }
                    let f = entry
                        .fields
                        .get_mut(usize::from(i))
                        .ok_or(AppError::InvalidInput)?;
                    if f.protected {
                        return Err(AppError::InvalidInput);
                    }
                    f.value =
                        qv_core::FieldValue::text(value).map_err(|_| AppError::InvalidInput)?;
                }
                _ => {}
            }
            Ok(())
        }
        WsField::Replacement(i) => {
            let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
            if usize::from(i) >= form.draft.entry().fields.len() {
                return Err(AppError::InvalidInput);
            }
            form.generated.retain(|g| *g != i);
            if value.is_empty() {
                form.replacements.remove(&i);
            } else {
                form.replacements.insert(i, protect(value.as_bytes())?);
            }
            if ws
                .reveal
                .as_ref()
                .is_some_and(|r| r.0 == RevealKey::Replacement(i))
            {
                ws.reveal = None;
            }
            Ok(())
        }
        WsField::GroupName => {
            let form = ws.group_form.as_mut().ok_or(AppError::InvalidInput)?;
            if value.is_empty() {
                return Err(AppError::InvalidInput);
            }
            form.draft.group_mut().name = text(value)?;
            Ok(())
        }
        WsField::GenLength | WsField::GenWords => {
            let n: u32 = value.parse().map_err(|_| AppError::InvalidInput)?;
            match (field, ws.generator.mode) {
                (WsField::GenWords, _) => ws.generator.words = n,
                (_, GenMode::Pin) => ws.generator.pin = n,
                _ => ws.generator.length = n,
            }
            Ok(())
        }
        WsField::GenSeparator => {
            let mut chars = value.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => ws.generator.separator = c,
                _ => return Err(AppError::InvalidInput),
            }
            Ok(())
        }
        WsField::GenExclude => {
            ws.generator.exclude = zeroize::Zeroizing::new(value.to_owned());
            Ok(())
        }
        WsField::VaultName | WsField::Description | WsField::HistoryDepth | WsField::TrashDays => {
            let draft = ws.settings.as_mut().ok_or(AppError::InvalidInput)?;
            let meta = draft.meta_mut();
            match field {
                WsField::VaultName => {
                    if value.is_empty() {
                        return Err(AppError::InvalidInput);
                    }
                    meta.name = text(value)?;
                }
                WsField::Description => {
                    meta.description = (!value.is_empty()).then(|| text(value)).transpose()?;
                }
                WsField::HistoryDepth => {
                    meta.settings.history_depth = parse_opt(value)?;
                }
                _ => meta.settings.trash_retention_days = parse_opt(value)?,
            }
            Ok(())
        }
        _ => {
            if value.is_empty() {
                ws.inputs.remove(&field);
            } else {
                ws.inputs.insert(field, protect(value.as_bytes())?);
            }
            Ok(())
        }
    }
}
fn parse_opt(value: &str) -> Result<Option<u32>, AppError> {
    if value.is_empty() {
        return Ok(None);
    }
    value.parse().map(Some).map_err(|_| AppError::InvalidInput)
}
#[cfg(test)]
pub(crate) fn backdate_reveal(ws: &mut Workspace, by: Duration) {
    if let Some(r) = ws.reveal.as_mut() {
        r.2 = r.2.checked_sub(by).unwrap_or(r.2);
    }
}
#[cfg(test)]
pub(crate) fn backdate_generated(ws: &mut Workspace, by: Duration) {
    if let Some(g) = ws.generated.as_mut() {
        g.1 = g.1.checked_sub(by).unwrap_or(g.1);
    }
}
