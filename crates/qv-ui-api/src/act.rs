// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the page asks the backend to do. Each variant maps to one existing
//! controller call; references name the handles the frame showed.
use crate::Ref;
use serde::{Deserialize, Serialize};

/// One bounded input. Values move to protected Rust storage on every
/// keystroke.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Field {
    /// A locked-screen input.
    Locked(LockedField),
    /// An unlocked workspace input.
    Ws(WsField),
    /// The LAN prompt's secret (password or recovery words).
    LanSecret {
        /// The prompt it answers.
        question: u64,
    },
}

/// Locked-screen inputs (`controller::InputField`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)] // Same names as controller::InputField.
pub enum LockedField {
    Path,
    Name,
    Password,
    Repeat,
    Phrase,
    Word0,
    Word1,
    Word2,
    LanCode,
    LanEndpoint,
}

/// Workspace inputs (`workspace::WsField`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)] // Same names as workspace::WsField.
pub enum WsField {
    Query,
    Command,
    Title,
    TypeHint,
    Notes,
    FieldName(u16),
    FieldValue(u16),
    Replacement(u16),
    NewFieldName,
    Start,
    GroupName,
    Path,
    Password,
    NewPassword,
    Repeat,
    Word(u8),
    GenLength,
    GenWords,
    GenSeparator,
    GenExclude,
    VaultName,
    Description,
    HistoryDepth,
    TrashDays,
    AttachMime,
    AttachName,
    Confirmation,
    LanCode,
    LanEndpoint,
    TotpInput,
}

impl WsField {
    /// The input's DOM id.
    pub fn dom_id(self) -> String {
        match self {
            Self::Query => "ws-query".into(),
            Self::Command => "palette-input".into(),
            Self::Title => "ws-title".into(),
            Self::TypeHint => "ws-type".into(),
            Self::Notes => "ws-notes".into(),
            Self::FieldName(i) => format!("ws-field-name-{i}"),
            Self::FieldValue(i) => format!("ws-field-value-{i}"),
            Self::Replacement(i) => format!("ws-replacement-{i}"),
            Self::NewFieldName => "ws-new-field".into(),
            Self::Start => "ws-start".into(),
            Self::GroupName => "ws-group-name".into(),
            Self::Path => "ws-path".into(),
            Self::Password => "ws-password".into(),
            Self::NewPassword => "ws-new-password".into(),
            Self::Repeat => "ws-repeat".into(),
            Self::Word(i) => format!("ws-word-{i}"),
            Self::GenLength => "ws-gen-length".into(),
            Self::GenWords => "ws-gen-words".into(),
            Self::GenSeparator => "ws-gen-separator".into(),
            Self::GenExclude => "ws-gen-exclude".into(),
            Self::VaultName => "ws-vault-name".into(),
            Self::Description => "ws-description".into(),
            Self::HistoryDepth => "ws-history-depth".into(),
            Self::TrashDays => "ws-trash-days".into(),
            Self::AttachMime => "ws-attach-mime".into(),
            Self::AttachName => "ws-attach-name".into(),
            Self::Confirmation => "ws-confirmation".into(),
            Self::LanCode => "ws-lan-code".into(),
            Self::LanEndpoint => "ws-lan-endpoint".into(),
            Self::TotpInput => "ws-totp-input".into(),
        }
    }

    /// Its length bound in characters (`maxlength`).
    pub fn limit(self, multiline: bool) -> usize {
        match self {
            Self::Query | Self::Command => QUERY_MAX,
            Self::Path => PATH_MAX,
            Self::Notes | Self::Replacement(_) | Self::TotpInput => MULTI_MAX,
            Self::FieldValue(_) if multiline => MULTI_MAX,
            _ => LINE_MAX,
        }
    }
}

/// Query bound (workspace::QUERY_MAX).
pub const QUERY_MAX: usize = 256;
/// Path bound (workspace::PATH_MAX).
pub const PATH_MAX: usize = 4096;
/// Single-line bound (workspace::LINE_MAX).
pub const LINE_MAX: usize = 1024;
/// Multi-line bound in characters (workspace::MULTI_MAX).
pub const MULTI_MAX: usize = 8 * 1024;

/// Window operations from the desktop title bar.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum WindowOp {
    /// Start moving the window with the pressed button.
    Drag,
    /// Maximize or restore.
    ToggleMaximize,
    /// Minimize.
    Minimize,
    /// Close.
    Close,
    /// Start resizing from an edge or corner.
    Resize(Edge),
    /// Window full screen (video), on or off.
    Fullscreen(bool),
}

/// A window edge or corner.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Edge {
    N,
    S,
    E,
    W,
    Ne,
    Nw,
    Se,
    Sw,
}

/// An entry or group.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ItemRef {
    /// An entry.
    Entry(Ref),
    /// A group.
    Group(Ref),
}

/// Settings panes (`workspace::Pane`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Pane {
    Overview,
    General,
    Password,
    Phrase,
    Rotation,
    Verify,
    Storage,
    About,
}

/// A screen to go to (`workspace::Screen`, handles as references).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Screen {
    Browse(Option<Ref>),
    Recovered,
    Search,
    Entry(Ref),
    Move(ItemRef, Option<Ref>),
    Trash,
    History(Ref),
    HistoryVersion(Ref, String),
    Conflicts,
    ConflictRecord(String),
    Attachments(Ref),
    Generator,
    Snapshots,
    Archives,
    Devices,
    Settings(Pane),
    Autofill,
    More,
    Kind(String),
}

/// What a reveal shows (`workspace::RevealKey`).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RevealKey {
    /// A current field.
    Field(Ref),
    /// A retained version's field: version ID, field ID reference.
    History(String, Ref),
    /// A conflicting version's field: record ID, version ID, field ID reference.
    Conflict(String, String, Ref),
    /// A protected replacement in the entry form.
    Replacement(u16),
    /// The generator's value.
    Generated,
    /// A TOTP field's current code.
    Totp(Ref),
    /// A Wi‑Fi entry's join QR.
    WifiJoin(Ref),
}

/// What a copy sends to the OS clipboard (`workspace::CopyKey`).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CopyKey {
    /// Entry, field.
    Field(Ref, Ref),
    /// Entry, TOTP field.
    Totp(Ref, Ref),
    /// The generator's value.
    Generated,
    /// An entry's notes.
    Notes(Ref),
}

/// Item types (`editor::ItemType`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ItemType {
    Login,
    Card,
    Wifi,
    Note,
    Other,
}

/// Field kinds (`qv_core::FieldKind`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum FieldKind {
    Text,
    Secret,
    Url,
    Email,
    Totp,
    Multiline,
    Date,
    Other,
}

/// Generator modes.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum GenMode {
    Characters,
    Words,
    Pin,
}

/// Generator toggles.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum GenFlag {
    Lower,
    Upper,
    Digits,
    Symbols,
    Ambiguous,
    Each,
    Capitalize,
    AppendDigit,
}

/// Quick-unlock policies.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QuickPolicy {
    /// Fingerprint.
    Class3,
    /// Screen-lock PIN or pattern.
    DeviceCredential,
}

/// Unlocked actions (`workspace::WsAction`), handles as references.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)] // Same meaning as workspace::WsAction.
pub enum WsAct {
    Search,
    Reveal(RevealKey),
    Hide,
    Copy(CopyKey),
    NewEntry(Ref),
    EditEntry(Ref),
    StartAs(Option<ItemType>),
    SetType(ItemType),
    SetGroup(Ref),
    SetHue(Option<u8>),
    AddField(Option<FieldKind>),
    /// A suggested name, by its index in the form's `common` list.
    AddNamedField(u8),
    MoveField(u16, bool),
    UndoRemoveField,
    UseGenerated(u16),
    RemoveField(u16),
    ToggleProtect(u16),
    GenerateInto(u16),
    SaveEntry,
    NewGroup(Ref),
    RenameGroup(Ref),
    SaveGroup,
    MoveTo(ItemRef, Ref),
    Delete(ItemRef),
    Restore(ItemRef),
    TrashMany(Vec<Ref>),
    RestoreMany(Vec<Ref>),
    MoveMany(Vec<Ref>, Ref),
    ColourMany(Vec<Ref>, Option<u8>),
    Preview(Ref),
    LoadPreview(Ref),
    PreviewStep(i8),
    ClosePreview,
    EmptyTrash,
    PurgeExpired,
    RestoreHistory(Ref, String, bool),
    PurgeHistory(Ref),
    Resolve(String, String),
    RestoreSnapshot(String),
    ExportArchive(bool),
    MergeArchive,
    AddAttachment(Ref),
    SaveAttachment(Ref),
    RemoveAttachment(Ref),
    GenMode(GenMode),
    GenToggle(GenFlag),
    Generate,
    SuggestPassword,
    SaveGeneratorDefaults,
    SaveSettings,
    ChangePassword,
    EnrollQuick(QuickPolicy),
    DisableQuick,
    AutofillFill(Ref),
    AutofillCancel,
    AutofillLink(Ref),
    OpenAutofillSettings,
    DeleteOldSnapshots,
    DeleteSnapshot(String),
    DeleteAllSnapshots,
    Compact,
    ShowPhrase,
    ConfirmWords,
    HidePhrase,
    BeginRotation,
    Verify,
    LanOffer,
    LanSync,
    Answer(bool),
    KeepSnapshots(bool),
    Dismiss,
    RatePassword,
    TotpOpen(Option<u16>),
    TotpCheck,
    TotpOptions(TotpOptions),
    TotpAdd,
    TotpClose,
}

/// A two-factor code's hash (`qv_core::OtpAlgorithm`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum OtpHash {
    Sha1,
    Sha256,
    Sha512,
}

/// Settings for a two-factor setup key (plan 0073).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct TotpOptions {
    /// 6–8.
    pub digits: u8,
    /// 30 or 60 seconds.
    pub period: u32,
    /// The hash.
    pub hash: OtpHash,
}

/// Locked-screen actions (`controller::Action`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)] // Same meaning as controller::Action.
pub enum Action {
    SuggestPassword,
    Create,
    ConfirmWeak,
    Unlock,
    ImportVault,
    QuickUnlock,
    Recover,
    RecoverPassword,
    ConfirmPhrase,
    SkipPhrase,
    AdoptBaseline,
    ConfirmRotation,
    InstallRotation,
    CancelRotation,
    ResumeComplete,
    ResumeRollback,
    JoinDevice,
}

/// The consent a locked action carries.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Consent {
    /// The controller's recorded consent (`Controller::consent`).
    Recorded,
    /// Given in this action.
    Given(bool),
}

/// Locked-screen workflows (`controller::Mode`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Mode {
    Unlock,
    Import,
    Create,
    Recover,
    Join,
}

/// Where switching vaults leads.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SwitchTo {
    /// A listed vault.
    Vault(Ref),
    /// A locked-screen workflow.
    Mode(Mode),
}

/// What a QR scan is for.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QrTarget {
    /// Join as a new device.
    NewDevice,
    /// Sync with the open vault.
    Sync,
    /// Set up a two-factor code.
    Totp,
}

/// Desktop file choices through the system picker.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Pick {
    /// Open a vault file (lists and selects it).
    Vault,
    /// The folder for new vaults.
    Folder,
    /// Where to save one new vault.
    NewVault,
    /// A file to add as an attachment, then add it to this entry.
    AddAttachment(Ref),
    /// Where to save an attachment, then save it.
    SaveAttachment(Ref),
    /// Where to restore a snapshot, then restore it.
    RestoreSnapshot(String),
    /// A folder to export an archive into (with the password slot or not).
    ExportArchive(bool),
    /// An archive to merge.
    MergeArchive,
}

/// Android document choices.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AndroidPick {
    /// Any file to read (attachments).
    Open,
    /// Where to write a file (attachments).
    Create,
    /// An archive to read.
    ArchiveOpen,
    /// Where to write an archive.
    ArchiveCreate,
}

/// Popovers whose content the backend reads, so their open state lives in
/// Rust like the page reads they own.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum UiOp {
    /// The command bar, open or closed.
    Palette(bool),
    /// A list row's copy menu (record ID), or none.
    CopyMenu(Option<String>),
    /// A list row's context menu (record ID), or none.
    RowMenu(Option<String>),
    /// The list head's group menu.
    GroupMenu(bool),
    /// The selection bar's popover.
    BarPop(Option<BarPop>),
    /// The editor's popover.
    EditorPop(Option<EditorPop>),
}

/// The selection bar's popovers.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum BarPop {
    /// Colour swatches.
    Colour,
    /// Move to a group.
    Move,
}

/// The editor's popovers; one at a time.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum EditorPop {
    Colour,
    Type,
    Group,
    Field(u16),
    Kind,
    Gen(u16),
}

/// Every typed action.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Act {
    /// Lock now.
    Lock,
    /// Set the theme (`dark`, `light`, `system`).
    Theme(String),
    /// A locked-screen action.
    Perform(Action, Consent),
    /// Acknowledge reduced protection, then run the gated action if any
    /// (with the recorded consent).
    AcknowledgeProtection(Option<Action>),
    /// The quick-unlock button was pressed (before its gated action).
    QuickStarted,
    /// Rate the new master password; sent once typing pauses (plan 0072).
    RatePassword,
    /// Choose a locked-screen workflow.
    SelectMode(Mode),
    /// Choose a listed vault (clears a typed path first).
    SelectVault(Ref),
    /// Remove a missing vault from the list.
    ForgetVault(Ref),
    /// Accept or decline the private-import acknowledgement.
    ImportAck(bool),
    /// Lock and switch to another vault or workflow.
    SwitchVault(SwitchTo),
    /// Lock, then open a vault file through the picker.
    SwitchToFile,
    /// A system file picker.
    Pick(Pick),
    /// An Android document picker.
    AndroidPick(AndroidPick),
    /// Go to a screen.
    Go(Screen),
    /// Select a list row (keeps a form open).
    Select(Screen),
    /// Back.
    Back,
    /// An unlocked action.
    Ws(WsAct),
    /// A list row's quick copy: its username (`false`) or password.
    QuickCopy(Ref, bool),
    /// Set or end the multi-selection (record IDs).
    Selection(Option<Vec<String>>),
    /// Start a QR scan.
    RequestQr(QrTarget),
    /// Cancel a QR scan.
    CancelQr,
    /// Answer the LAN prompt.
    LanAnswer(u64, bool),
    /// Cancel the LAN operation.
    LanCancel,
    /// Keep the LAN receipt open.
    LanKeep,
    /// Close the LAN receipt.
    LanDismiss,
    /// Close the receipt and open the conflicts.
    LanResolve,
    /// Open a changed entry from the receipt.
    LanOpen(Ref),
    /// A popover whose content Rust reads.
    Ui(UiOp),
    /// Validation builds only: a synthetic flow's report.
    Fixture(String),
}
