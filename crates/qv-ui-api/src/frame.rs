// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frames: what one screen shows, built in Rust from the controller's reads
//! (plan 0071). Display decisions that depend on Rust state are made there
//! too; the page adds only its own local state (open menus, sheets, typed
//! text).
use crate::act::{
    BarPop, CopyKey, EditorPop, FieldKind, GenMode, ItemRef, ItemType, Mode, Pane, QuickPolicy,
    RevealKey, Screen, WsAct,
};
use crate::{Ref, Z};
use serde::{Deserialize, Serialize};

/// The app's icons; the page holds the paths.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Icon {
    Lock,
    Search,
    Plus,
    ChevronDown,
    Up,
    Right,
    Back,
    All,
    Key,
    Note,
    Card,
    Wifi,
    Generator,
    Devices,
    Trash,
    Conflicts,
    Settings,
    Copy,
    User,
    Eye,
    EyeOff,
    Edit,
    More,
    History,
    Attach,
    Move,
    Globe,
    Sun,
    Moon,
    Minimize,
    Maximize,
    Close,
    Shield,
    Check,
    Finger,
    File,
    Folder,
    Refresh,
    Qr,
    Warn,
    Archive,
    Clock,
    Restore,
    Palette,
    Play,
    Pause,
    Volume,
    Muted,
    Expand,
    Shrink,
}

/// The platform the backend runs on.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Platform {
    Linux,
    Android,
    Windows,
}

/// One whole screen.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Frame {
    /// Increases with every frame.
    pub seq: u64,
    /// The controller's form epoch; actions carry it back.
    pub epoch: u64,
    /// The theme's `data-mode` (`dark`, `light`, `system`).
    pub mode: String,
    /// The platform.
    pub platform: Platform,
    /// The desktop title bar.
    pub title: TitleBar,
    /// The body.
    pub body: Body,
    /// Validation builds only.
    pub fixture: Option<Fixture>,
}

/// Validation-build hooks.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Fixture {
    /// The synthetic vault's private root (a test path).
    pub root: String,
    /// The synthetic LAN peer opened its vault.
    pub peer_opened: bool,
}

/// A listed vault (names are not secret, 0009 §1.8).
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct VaultChoice {
    /// Its reference.
    pub id: Ref,
    /// Its name.
    pub name: Z,
    /// Its file name.
    pub file: Z,
    /// Its folder, for display.
    pub place: Z,
    /// The file is there.
    pub exists: bool,
    /// Found by scanning a folder.
    pub in_folder: bool,
    /// The open vault.
    pub current: bool,
    /// Quick unlock is enrolled for it.
    pub quick: bool,
    /// Its colour class.
    pub hue: String,
    /// Its monogram.
    pub initial: String,
}

/// The desktop title bar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TitleBar {
    /// A vault is open.
    pub unlocked: bool,
    /// Seconds to the inactivity lock.
    pub idle_left: u64,
    /// An operation runs.
    pub busy: bool,
    /// The open vault's name.
    pub vault: Option<Z>,
    /// Only idle locking works here.
    pub idle_only: bool,
    /// The light theme is on.
    pub light: bool,
    /// The controller is up (theme toggle, lock).
    pub ready: bool,
    /// The vault switcher's vaults.
    pub vaults: Vec<VaultChoice>,
    /// A form holds unsaved input.
    pub editing: bool,
}

/// The body under the title bar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Body {
    /// The controller could not start.
    Failed {
        /// Heading.
        title: String,
        /// Explanation.
        message: String,
    },
    /// The locked screens.
    Locked(Box<Locked>),
    /// The unlocked shell.
    Unlocked(Box<Shell>),
}

/// One protection check.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct StatusRow {
    /// Label.
    pub label: String,
    /// CSS classes of the value.
    pub class: String,
    /// Value.
    pub text: String,
}

/// Device protection (0009 §1.8).
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Protection {
    /// Level name.
    pub label: String,
    /// Level tone.
    pub tone: String,
    /// Something is reduced.
    pub reduced: bool,
    /// The checks.
    pub rows: Vec<StatusRow>,
    /// Quick unlock is available.
    pub quick_unlock: bool,
}

/// Locked-screen phases (`controller::Phase`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Phase {
    Locked,
    WeakPassword,
    Opening,
    Phrase,
    Recovery,
    Unlocked,
    Rotation,
}

/// The locked screens.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Locked {
    /// Workflow.
    pub mode: Mode,
    /// Phase.
    pub phase: Phase,
    /// An operation runs.
    pub busy: bool,
    /// Read-only UI preview build.
    pub preview: bool,
    /// Validation fixture.
    pub fixture: bool,
    /// Error message.
    pub error: Option<String>,
    /// Notice.
    pub notice: Option<String>,
    /// A picked vault file's name.
    pub picked: Option<Z>,
    /// No vault yet.
    pub first_run: bool,
    /// Listed vaults.
    pub vaults: Vec<VaultChoice>,
    /// The selected vault.
    pub selected: Option<VaultChoice>,
    /// The folder new vaults go to.
    pub folder_place: Z,
    /// The recovery phrase (phrase and rotation phases only).
    pub words: Vec<Z>,
    /// The visible passphrase suggestion.
    pub suggestion: Option<Z>,
    /// Vault files can be picked here.
    pub can_pick: bool,
    /// No system picker answered (or a fixture).
    pub fallback: bool,
    /// A typed path input is shown (fixtures).
    pub typed_path: bool,
    /// Quick unlock is offered first.
    pub quick: bool,
    /// Its button label.
    pub quick_label: String,
    /// Device protection.
    pub protection: Protection,
    /// Reduced protection awaits acknowledgement (footer chip).
    pub ack_needed: bool,
    /// Actions are gated on that acknowledgement (the page opens the
    /// protection sheet first).
    pub gate: bool,
    /// An interrupted rotation: needs the new and the old password.
    pub resume: Option<(bool, bool)>,
    /// The rotation's new phrase is confirmed.
    pub rotation_confirmed: bool,
    /// Requested word positions.
    pub positions: [usize; 3],
    /// Seconds before a weak password may be confirmed.
    pub weak_seconds: u64,
    /// The password is fair.
    pub fair_warning: bool,
    /// The live rating of the new master password (plan 0072).
    pub meter: Option<StrengthMeter>,
    /// The suggestion shows.
    pub suggestion_visible: bool,
    /// The two passwords differ.
    pub mismatch: bool,
    /// The import's local file name.
    pub import_name: Z,
    /// The import is ready for its password.
    pub import_ready: bool,
    /// The import is acknowledged.
    pub import_ack: bool,
    /// The join code came from a scan.
    pub code_scanned: bool,
    /// A scanned join waits only for the protection review (plan 0072).
    pub join_review: bool,
    /// Quick unlock prompts by itself for this foreground entry.
    pub autoprompt: Option<u64>,
    /// The autofill banner.
    pub autofill_banner: Option<String>,
    /// The LAN operation.
    pub lan: Option<Lan>,
    /// A QR scan runs.
    pub scanning: bool,
    /// The camera can scan.
    pub camera: bool,
}

/// Time-dependent display.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub struct Live {
    /// Seconds before the reveal hides.
    pub reveal_left: u64,
    /// Seconds before the clipboard clears.
    pub clipboard: u64,
    /// Seconds before weak-password consent.
    pub weak_seconds: u64,
}

/// A paged list's navigation.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct PageNav {
    /// The slot to turn.
    pub slot: String,
    /// The read serial.
    pub serial: u64,
    /// There is a previous page.
    pub previous: bool,
    /// There is a next page.
    pub next: bool,
    /// A page loads.
    pub loading: bool,
    /// A read failed.
    pub error: Option<String>,
    /// A scrolling list (plan 0072): `next` loads more when the end comes
    /// into view while `more` is set, otherwise it offers "Show more";
    /// `previous` offers "Back to the start".
    pub window: bool,
    /// The window can take another page.
    pub more: bool,
}

/// A row's glyph: its type's icon, or the title's monogram.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Glyph {
    /// An icon.
    Icon(Icon),
    /// A letter.
    Letter(String),
}

/// The unlocked shell.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Shell {
    /// Workspace revision.
    pub revision: u64,
    /// Actions are disabled.
    pub busy: bool,
    /// Progress shows.
    pub busy_shown: bool,
    /// A QR scan runs.
    pub scanning: bool,
    /// The scan is for a two-factor code (plan 0073).
    pub scanning_totp: bool,
    /// Countdowns.
    pub live: Live,
    /// Android validation banner.
    pub fixture_banner: bool,
    /// The rollback record may travel with the vault.
    pub anchor_warning: bool,
    /// A vault screen (list + detail).
    pub vault_screen: bool,
    /// A confirmation is pending (the shell is inert).
    pub inert: bool,
    /// The sidebar.
    pub sidebar: Sidebar,
    /// The content.
    pub content: Content,
    /// The floating new-item button.
    pub fab: bool,
    /// Which phone tab is on: vault, generator, sync, settings.
    pub tabs: [bool; 4],
    /// The busy toast.
    pub busy_toast: bool,
    /// The LAN operation.
    pub lan: Option<Lan>,
    /// The phone vault sheet's vaults and state.
    pub cards: VaultCards,
    /// The open preview.
    pub viewer: Option<Box<Viewer>>,
    /// The pending confirmation.
    pub confirm: Option<Confirm>,
    /// Toasts.
    pub toasts: Toasts,
    /// The command bar, while open.
    pub palette: Option<Palette>,
    /// Where a new item goes.
    pub new_in: Option<Ref>,
    /// The root group.
    pub root: Option<Ref>,
    /// The light theme is on.
    pub light: bool,
}

/// The phone vault sheet.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct VaultCards {
    /// Vaults.
    pub vaults: Vec<VaultChoice>,
    /// The open vault has quick unlock.
    pub open_quick: bool,
    /// A form holds unsaved input.
    pub editing: bool,
}

/// Toasts.
#[derive(Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct Toasts {
    /// Clipboard seconds left.
    pub clipboard: u64,
    /// Error.
    pub error: Option<String>,
    /// Notice.
    pub notice: Option<String>,
    /// Undo for the notice.
    pub undo: Option<WsAct>,
}

/// The sidebar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Sidebar {
    /// Live entries.
    pub total: usize,
    /// "All items" is on.
    pub all_on: bool,
    /// The five types.
    pub types: Vec<TypeNav>,
    /// The type counts failed.
    pub kind_error: Option<String>,
    /// The root group (New group).
    pub root: Option<Ref>,
    /// Top-level groups.
    pub groups: Vec<GroupNav>,
    /// Their pages.
    pub group_page: Option<PageNav>,
    /// Recovered items.
    pub recovered: usize,
    /// "Recovered items" is on.
    pub recovered_on: bool,
    /// Tools.
    pub tools: Vec<ToolNav>,
    /// Settings is on.
    pub settings_on: bool,
}

/// A type in the sidebar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TypeNav {
    /// Its bucket.
    pub kind: String,
    /// Its label.
    pub label: String,
    /// It is on.
    pub on: bool,
    /// Its count, once known.
    pub count: Option<usize>,
    /// Its icon.
    pub icon: Icon,
}

/// A group in the sidebar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupNav {
    /// The group.
    pub id: Ref,
    /// Its name.
    pub name: Z,
    /// Its colour class.
    pub hue: String,
    /// Live entries.
    pub entries: usize,
    /// It is on.
    pub on: bool,
}

/// A tool in the sidebar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ToolNav {
    /// Where it goes.
    pub target: Screen,
    /// Label.
    pub label: String,
    /// Icon.
    pub icon: Icon,
    /// DOM id.
    pub id: String,
    /// Badge count.
    pub count: usize,
    /// It is on.
    pub on: bool,
}

/// The main content.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    /// A vault screen: list and detail.
    Vault {
        /// The list.
        list: Box<ListPane>,
        /// The detail.
        detail: Box<Detail>,
    },
    /// A section page.
    Page(Box<Page>),
}

/// What a list row copies.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RowCopy {
    /// Nothing.
    None,
    /// Username and password buttons.
    Pair {
        /// A username.
        user: bool,
        /// A password.
        secret: bool,
    },
    /// The password.
    Secret,
    /// A menu of fields.
    Menu,
}

/// A list row.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Row {
    /// The entry.
    pub id: Ref,
    /// Its record ID (selection key).
    pub rid: String,
    /// Title.
    pub title: Z,
    /// Subtitle (or the type's name).
    pub sub: Z,
    /// Tile colour class.
    pub hue: String,
    /// Tile glyph.
    pub glyph: Glyph,
    /// Conflicted.
    pub conflict: bool,
    /// What it copies.
    pub copy: RowCopy,
    /// A card.
    pub card: bool,
    /// Its chosen colour.
    pub colour: Option<u8>,
}

/// One letter's rows.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Section {
    /// The letter.
    pub letter: String,
    /// Rows.
    pub rows: Vec<Row>,
}

/// A field in a copy menu (no value).
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct MenuField {
    /// The field.
    pub field: Ref,
    /// Its name.
    pub name: Z,
    /// Its icon.
    pub icon: Icon,
    /// A two-factor code field: copying it copies the current code.
    pub code: bool,
}

/// A group chip.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Chip {
    /// Where it goes.
    pub target: Screen,
    /// Name.
    pub name: Z,
    /// Colour class (top-level chips).
    pub hue: String,
    /// It is on.
    pub on: bool,
}

/// A bounded group picker.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupChoices {
    /// "No group".
    pub root: Option<Ref>,
    /// Groups: id, name, colour class, current.
    pub groups: Vec<(Ref, Z, String, bool)>,
    /// A nested current group not in the page.
    pub extra: Option<(Ref, Z)>,
    /// Pages.
    pub page: Option<PageNav>,
}

/// Which list.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ListKind {
    All,
    Group,
    Kind,
    Recovered,
    Search,
}

/// The list beside the detail.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ListPane {
    /// Which list.
    pub kind: ListKind,
    /// Title.
    pub title: Z,
    /// Rows shown.
    pub count: usize,
    /// A held page shows while its replacement loads.
    pub stale: bool,
    /// The first page has loaded.
    pub loaded: bool,
    /// The shown group.
    pub group: Option<Ref>,
    /// Rows are disabled (a form or an operation).
    pub form: bool,
    /// Multi-selection is on (and no form).
    pub in_selection: bool,
    /// Selected record IDs.
    pub chosen: Vec<String>,
    /// Shown record IDs and entries, in order.
    pub order: Vec<(String, Ref)>,
    /// The open entry.
    pub current: Option<Ref>,
    /// The filter's value.
    pub query: Z,
    /// The filter's label and placeholder.
    pub filter: String,
    /// The filter's placeholder.
    pub placeholder: String,
    /// Focus the filter (Search).
    pub autofocus: bool,
    /// Pages.
    pub page: Option<PageNav>,
    /// Top-level group chips (phone), with New group.
    pub chips: Option<(Vec<Chip>, Option<Ref>)>,
    /// Subgroup chips.
    pub subgroups: Vec<Chip>,
    /// Conflicted items.
    pub conflicts: usize,
    /// Rows by letter.
    pub sections: Vec<Section>,
    /// The empty list's text and icon.
    pub empty: (String, Icon),
    /// The open vault's tile (phone head).
    pub vault: Option<VaultChoice>,
    /// Recovered items link (All items).
    pub recovered: usize,
    /// Where a new item goes.
    pub new_in: Option<Ref>,
    /// The group menu is open.
    pub group_menu: bool,
    /// The selection bar's popover.
    pub bar_pop: Option<BarPop>,
    /// Groups to move the selection to (while that popover is open).
    pub move_choices: Option<GroupChoices>,
    /// The open copy menu: record ID and fields.
    pub copy_menu: Option<(String, Vec<MenuField>)>,
    /// The open row menu: record ID and, for menu rows, fields.
    pub row_menu: Option<(String, Vec<MenuField>)>,
}

/// A finished task's result.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ReportCard {
    /// It went well.
    pub ok: bool,
    /// Lines.
    pub lines: Vec<String>,
}

/// The detail pane.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Detail {
    /// Nothing is open (a list screen).
    pub closed: bool,
    /// A report.
    pub report: Option<ReportCard>,
    /// What shows.
    pub inner: DetailInner,
}

/// The detail's content.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DetailInner {
    /// Select an item.
    Empty,
    /// Loading or an error message.
    Unreadable(String),
    /// An entry.
    Entry(Box<EntryScreen>),
    /// The entry editor.
    EditEntry(Box<Editor>),
    /// The group editor.
    EditGroup(GroupEditor),
    /// Move to a group.
    Move(MoveScreen),
    /// History.
    History(HistoryScreen),
    /// A retained version.
    Version(Box<VersionScreen>),
    /// Attachments.
    Attachments(AttachmentsScreen),
}

/// A card's face (never its number).
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct CardFace {
    /// Brand.
    pub brand: String,
    /// Masked number with its last four.
    pub number: String,
    /// Name on the card.
    pub name: Z,
    /// Expiry.
    pub expiry: Z,
}

/// A QR symbol as an SVG path.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Qr {
    /// Side with the quiet zone.
    pub side: usize,
    /// The path.
    pub path: Z,
}

/// One field of an entry.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct FieldLine {
    /// Name.
    pub name: Z,
    /// Kind name.
    pub kind_name: String,
    /// A TOTP field.
    pub totp: bool,
    /// Plain value.
    pub value: Option<Z>,
    /// Protected.
    pub protected: bool,
    /// The revealed value.
    pub shown: Option<Z>,
    /// The current TOTP code (no reveal needed, plan 0073).
    pub code: Option<Code>,
    /// Its reveal.
    pub reveal: RevealKey,
    /// Its code's reveal (TOTP).
    pub code_key: Option<RevealKey>,
    /// Its copy, when it may be copied.
    pub copy: Option<CopyKey>,
}

/// An entry's fields and notes.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct EntryBody {
    /// The entry.
    pub entry: Ref,
    /// Current (not a retained version).
    pub current: bool,
    /// Title.
    pub title: Z,
    /// Tile colour class.
    pub tile: String,
    /// Tile glyph.
    pub glyph: Glyph,
    /// The first URL.
    pub url: Option<Z>,
    /// Type hint.
    pub type_hint: Z,
    /// Its icon.
    pub kind_icon: Icon,
    /// Group name and colour class.
    pub group: Option<(Z, String)>,
    /// Active versions.
    pub versions: usize,
    /// Record ID.
    pub record: String,
    /// Expiry.
    pub expires: Option<String>,
    /// A card's face.
    pub card: Option<CardFace>,
    /// The Wi‑Fi join card: entry, QR while revealed.
    pub wifi: Option<Option<Qr>>,
    /// Fields.
    pub fields: Vec<FieldLine>,
    /// Notes.
    pub notes: Option<Z>,
}

/// A file on the shelf.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct FileTile {
    /// The attachment.
    pub id: Ref,
    /// Name.
    pub name: Z,
    /// Tone class.
    pub tone: String,
    /// Icon.
    pub icon: Icon,
    /// Conflicted.
    pub conflicted: bool,
    /// Size text.
    pub size: String,
}

/// An entry screen.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct EntryScreen {
    /// The entry.
    pub entry: Ref,
    /// It may be edited.
    pub editable: bool,
    /// In the trash.
    pub deleted: bool,
    /// Attachment count.
    pub attachments: usize,
    /// Body.
    pub body: EntryBody,
    /// Files.
    pub files: Vec<FileTile>,
    /// Modified.
    pub modified: String,
    /// Created.
    pub created: String,
}

/// A suggested type on the start step.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TypeChoice {
    /// The type.
    pub kind: ItemType,
    /// Its name.
    pub name: String,
    /// Its hint (DOM ids).
    pub hint: String,
    /// Its icon.
    pub icon: Icon,
    /// Its tile colour class.
    pub hue: String,
}

/// The entry editor.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Editor {
    /// "What are you saving?"
    Start {
        /// The guess: type, headline, second line.
        guess: Option<(TypeChoice, Z, Z)>,
        /// Every type.
        types: Vec<TypeChoice>,
    },
    /// The form.
    Form(Box<Form>),
}

/// How the editor shows a field.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Role {
    Plain,
    Password,
    Hidden,
    CardNumber,
    Expiry,
    Security,
}

/// One form row.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct FormRow {
    /// Index in the draft.
    pub index: u16,
    /// Name.
    pub name: Z,
    /// Kind.
    pub kind: FieldKind,
    /// Protected.
    pub protected: bool,
    /// Plain value.
    pub value: Option<Z>,
    /// A replacement is set.
    pub replaced: bool,
    /// It was generated.
    pub generated: bool,
    /// It was filled from the start box.
    pub filled: bool,
    /// Too large to edit here.
    pub too_large: bool,
    /// A protected value is saved.
    pub stored: bool,
    /// Role.
    pub role: Role,
    /// The revealed replacement.
    pub shown: Option<Z>,
    /// The masked text.
    pub masked: String,
    /// A check: text and classes.
    pub check: Option<(String, String)>,
    /// Placeholder.
    pub placeholder: String,
    /// A two-factor field's current code.
    pub code: Option<Code>,
}

/// A two-factor code at this moment (plan 0073).
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Code {
    /// The digits, grouped for reading ("123 456").
    pub code: Z,
    /// Seconds until the next code.
    pub left: u32,
    /// The code's time step in seconds.
    pub period: u32,
}

/// The two-factor setup sheet (plan 0073).
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TotpSheet {
    /// It replaces a field's code.
    pub replacing: bool,
    /// A camera scan exists here.
    pub can_scan: bool,
    /// The input came from a scan.
    pub scanned: bool,
    /// Settings for a setup key.
    pub options: crate::act::TotpOptions,
    /// What the last check found.
    pub state: TotpState,
}

/// What the setup sheet's last check found.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TotpState {
    /// Nothing typed yet.
    Empty,
    /// Refused, with why.
    Invalid(String),
    /// A setup key, with its current code.
    Key(Option<Code>),
    /// A link (its own settings apply), with its current code.
    Link(Option<Code>),
}

/// The generator popover.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct GenPopover {
    /// The value.
    pub value: Option<Z>,
    /// Passphrase mode.
    pub words: bool,
    /// Length or words.
    pub n: u32,
    /// Range.
    pub min: u32,
    /// Range.
    pub max: u32,
    /// Symbols on.
    pub symbols: bool,
    /// Strength text.
    pub bits: Option<String>,
}

/// The entry form.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Form {
    /// Record ID.
    pub id: String,
    /// A new entry.
    pub new: bool,
    /// Its type.
    pub kind: ItemType,
    /// Its type's name.
    pub type_name: String,
    /// Its icon.
    pub icon: Icon,
    /// A note.
    pub is_note: bool,
    /// Tile colour class.
    pub hue: String,
    /// Chosen colour.
    pub colour: Option<u8>,
    /// Title.
    pub title: Z,
    /// Title placeholder.
    pub placeholder: Z,
    /// Where the automatic title comes from, while the title is empty.
    pub auto_from: Option<String>,
    /// Focus the title.
    pub title_focus: bool,
    /// The group: name and colour class.
    pub group: Option<(Z, String)>,
    /// Rows.
    pub rows: Vec<FormRow>,
    /// The row to focus.
    pub focus: Option<u16>,
    /// The removed field, for Undo.
    pub removed: Option<Z>,
    /// The new field's suggested kind.
    pub new_kind: FieldKind,
    /// Notes.
    pub notes: Z,
    /// Notes too large.
    pub notes_too_large: bool,
    /// Notes start open.
    pub notes_open: bool,
    /// Focus the notes.
    pub notes_focus: bool,
    /// A card's face.
    pub card: Option<CardFace>,
    /// Wi‑Fi: network name, security label.
    pub wifi: Option<(Z, String)>,
    /// A save would pass.
    pub ready: bool,
    /// The replacement whose eye is on.
    pub showing: Option<u16>,
    /// The open popover.
    pub pop: Option<EditorPop>,
    /// The generator popover.
    pub generator: Option<GenPopover>,
    /// The group picker (while open).
    pub group_choices: Option<GroupChoices>,
    /// Every type.
    pub types: Vec<TypeChoice>,
    /// Common field names for this type.
    pub common: Vec<String>,
    /// Kinds for a new field: kind, label.
    pub add_kinds: Vec<(FieldKind, String)>,
    /// Wi‑Fi security choices: value, label.
    pub security: Vec<(String, String)>,
    /// Labels of every field kind, for the kind pill.
    pub kind_labels: Vec<(FieldKind, String)>,
    /// A login without a two-factor field: offer to set one up.
    pub totp_slot: bool,
    /// The open two-factor setup sheet.
    pub totp_sheet: Option<TotpSheet>,
}

/// The group editor.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct GroupEditor {
    /// A new group.
    pub new: bool,
    /// Tile colour class.
    pub hue: String,
    /// Name.
    pub name: Z,
    /// Chosen colour.
    pub colour: Option<u8>,
}

/// Move to a group.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct MoveScreen {
    /// What moves.
    pub item: ItemRef,
    /// Breadcrumbs.
    pub crumbs: Vec<(Ref, Z)>,
    /// The empty level's text.
    pub empty: Option<Z>,
    /// Groups here.
    pub groups: Vec<(Ref, Z)>,
    /// The shown group.
    pub here: Ref,
    /// Pages.
    pub page: Option<PageNav>,
}

/// One retained version.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct HistoryRow {
    /// Version ID.
    pub version: String,
    /// Modified.
    pub modified: String,
    /// What changed.
    pub changed: Z,
    /// Concurrent.
    pub conflict: bool,
}

/// History.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct HistoryScreen {
    /// The entry.
    pub entry: Ref,
    /// Rows.
    pub rows: Vec<HistoryRow>,
}

/// A retained version.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct VersionScreen {
    /// The entry.
    pub entry: Ref,
    /// Version ID.
    pub version: String,
    /// Body.
    pub body: EntryBody,
    /// The entry is conflicted.
    pub conflicted: bool,
}

/// How files are chosen here.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Picker {
    /// The system picker.
    Portal,
    /// A typed path.
    Typed,
    /// Android documents, with the chosen name.
    Android(Option<Z>),
}

/// An attachment row.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Attachment {
    /// The attachment.
    pub id: Ref,
    /// Name.
    pub name: Z,
    /// MIME type.
    pub mime: Z,
    /// Size in bytes.
    pub size: u64,
    /// Conflicted.
    pub conflicted: bool,
}

/// Attachments.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct AttachmentsScreen {
    /// The entry.
    pub entry: Ref,
    /// Rows.
    pub rows: Vec<Attachment>,
    /// File choice.
    pub picker: Picker,
}

/// The preview viewer.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Viewer {
    /// Remount key (version ID).
    pub key: String,
    /// The attachment.
    pub id: Ref,
    /// Its entry.
    pub entry: Ref,
    /// Name.
    pub name: Z,
    /// `image`, `audio`, `video`, `text` or `file`.
    pub kind: String,
    /// Kind name.
    pub kind_name: String,
    /// Sniffed type.
    pub mime: String,
    /// Size in bytes.
    pub size: u64,
    /// Size text.
    pub size_label: String,
    /// The media URL.
    pub src: Option<Z>,
    /// Text.
    pub text: Option<Z>,
    /// Text lines.
    pub lines: usize,
    /// Text continues.
    pub cut: bool,
    /// An image waiting for consent: its description.
    pub image_load: Option<String>,
    /// Position.
    pub index: usize,
    /// Count.
    pub count: usize,
    /// Tone class.
    pub tone: String,
    /// Icon.
    pub icon: Icon,
    /// Save through the system picker.
    pub direct_save: bool,
}

/// A confirmation.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Confirm {
    /// Message.
    pub message: String,
    /// The weak-password confirmation.
    pub weak: bool,
    /// Snapshots holding the data.
    pub holding: usize,
    /// "Keep in snapshots" is ticked.
    pub keep: bool,
    /// Seconds before it may continue.
    pub seconds: u64,
}

/// An item in the command bar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Hit {
    /// The entry.
    pub id: Ref,
    /// Tile colour class.
    pub hue: String,
    /// Glyph.
    pub glyph: Glyph,
    /// Title.
    pub title: Z,
    /// Subtitle.
    pub sub: Z,
}

/// The command bar.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Palette {
    /// The query.
    pub query: Z,
    /// Matching items.
    pub hits: Vec<Hit>,
    /// Matching groups.
    pub groups: Vec<(Ref, Z)>,
    /// Pages.
    pub page: Option<PageNav>,
}

/// A LAN question.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Question {
    Approve { sas: String, vault: String },
    JoinVault { vault: String, sas: String },
    ChooseCredential,
    RecoveryPhrase,
    JoinRecoveredVault { vault: String },
    Password { offering: bool, retry: bool },
}

/// A finished LAN operation.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Receipt {
    /// Tone class.
    pub tone: String,
    /// Title.
    pub title: String,
    /// Second line.
    pub sub: String,
    /// Icon.
    pub icon: Icon,
    /// New, changed, trashed.
    pub counts: [usize; 3],
    /// Total changes.
    pub total: usize,
    /// Changes: mark, entry, title.
    pub listed: Vec<(String, Option<Ref>, Z)>,
    /// Conflicts.
    pub conflicts: usize,
    /// Countdown ring offset.
    pub ring: Option<String>,
}

/// The LAN operation.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Lan {
    /// The outcome.
    pub done: Option<Receipt>,
    /// Title.
    pub title: String,
    /// Window or sync (names the vault).
    pub names_vault: bool,
    /// The open vault: name, colour class.
    pub vault: Option<(Z, String)>,
    /// The QR code.
    pub qr: Option<Qr>,
    /// The code.
    pub code: Option<Z>,
    /// This device's addresses.
    pub endpoints: Vec<String>,
    /// Seconds left.
    pub seconds: u64,
    /// The other device is admitted.
    pub admitted: bool,
    /// The comparison code while waiting.
    pub sas: Option<String>,
    /// Progress.
    pub info: Option<String>,
    /// The question.
    pub question: Option<Question>,
    /// Its id.
    pub question_id: u64,
}

/// A section page.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Page {
    /// Remount key.
    pub key: String,
    /// A report.
    pub report: Option<ReportCard>,
    /// The page.
    pub body: PageBody,
}

/// Section pages.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum PageBody {
    Empty,
    Unreadable(String),
    Generator(Generator),
    Devices(Devices),
    Trash(Trash),
    Conflicts(Conflicts),
    Compare(Box<Compare>),
    Snapshots(Snapshots),
    Archives(Archives),
    Settings(Box<Settings>),
    Autofill(Box<Autofill>),
}

/// The generator.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Generator {
    /// The value.
    pub value: Option<Z>,
    /// Mode.
    pub mode: GenMode,
    /// Length.
    pub length: u32,
    /// Words.
    pub words: u32,
    /// PIN digits.
    pub pin: u32,
    /// Toggles.
    pub flags: [bool; 8],
    /// Separator.
    pub separator: String,
    /// Excluded characters.
    pub exclude: Z,
    /// Entropy.
    pub bits: Option<f64>,
}

/// Sync.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Devices {
    /// A scanned code waits for its address.
    pub scanned: bool,
    /// The camera can scan.
    pub scan: bool,
    /// The open vault.
    pub vault: Option<VaultChoice>,
    /// An operation runs.
    pub busy: bool,
}

/// A trash row.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TrashRow {
    /// The item.
    pub item: ItemRef,
    /// Name.
    pub name: Z,
    /// Colour class.
    pub hue: String,
    /// Monogram.
    pub initial: String,
    /// When deleted.
    pub deleted: String,
    /// Conflicted.
    pub conflict: bool,
}

/// Trash.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Trash {
    /// Clock warning.
    pub clock_anomaly: bool,
    /// Rows.
    pub items: Vec<TrashRow>,
    /// The first page has loaded.
    pub loaded: bool,
    /// Expired items.
    pub expired: usize,
    /// Pages.
    pub page: Option<PageNav>,
}

/// A conflicted record.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ConflictRow {
    /// Record ID.
    pub record: String,
    /// Name or kind.
    pub name: Z,
    /// Kind.
    pub kind: String,
    /// Versions.
    pub versions: usize,
}

/// Conflicts.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Conflicts {
    /// Rows.
    pub rows: Vec<ConflictRow>,
    /// The first page has loaded.
    pub loaded: bool,
    /// Pages.
    pub page: Option<PageNav>,
}

/// A comparison cell.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Cell {
    /// Empty text.
    Empty,
    /// Text.
    Text(Z),
    /// Not in this version.
    Missing,
    /// A protected value and its reveal.
    Masked(RevealKey, Option<Z>),
    /// The same protected value in every version (never shown).
    SameProtected,
}

/// A version's column head.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Head {
    /// Letter.
    pub label: String,
    /// Version ID.
    pub version: String,
    /// State.
    pub state: String,
    /// Modified.
    pub modified: String,
}

/// A conflict comparison.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Compare {
    /// Record ID.
    pub record: String,
    /// Lead text.
    pub lead: String,
    /// The versions look the same.
    pub identical: bool,
    /// Choosing needs a password.
    pub needs_password: bool,
    /// Kind label.
    pub kind: String,
    /// Column class.
    pub cols: String,
    /// Heads.
    pub heads: Vec<Head>,
    /// Differing rows: label, cells.
    pub diff: Vec<(Z, Vec<Cell>)>,
    /// Same rows: label, first cell.
    pub same: Vec<(Z, Cell)>,
}

/// A snapshot row.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Snapshot {
    /// Archive ID.
    pub id: String,
    /// Created.
    pub created: String,
    /// Kind.
    pub kind: String,
    /// Size text.
    pub size: String,
}

/// Snapshots.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Snapshots {
    /// Rows.
    pub rows: Vec<Snapshot>,
    /// Unreadable files.
    pub unreadable: u64,
    /// Size kept only by snapshots.
    pub kept: String,
    /// A typed path or name: its label.
    pub typed: Option<String>,
    /// Restore through the system picker.
    pub portal: bool,
}

/// Archives.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Archives {
    /// How files are chosen.
    pub picker: Picker,
}

/// Settings.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Settings {
    /// The pane.
    pub pane: Pane,
    /// Nested (has a back link).
    pub nested: bool,
    /// The pane's content.
    pub body: SettingsBody,
}

/// Settings panes.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum SettingsBody {
    Overview(Box<Overview>),
    General(Option<General>),
    Password(PasswordPane),
    Phrase(PhrasePane),
    Rotation(Guidance),
    Verify,
    Storage(Result<Storage, String>),
    About(About),
}

/// The settings home.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Overview {
    /// Theme name.
    pub theme: String,
    /// Only idle locking works.
    pub idle_only: bool,
    /// Protection detail.
    pub detail: String,
    /// Level label.
    pub level: String,
    /// Level tone.
    pub tone: String,
    /// The quick-unlock row's line.
    pub quick: String,
    /// The open vault: file, place.
    pub file: Option<(Z, Z)>,
    /// Folder for new vaults.
    pub folder: Z,
    /// The folder can be changed through the picker.
    pub folder_change: bool,
}

/// Name and retention.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct General {
    /// Name.
    pub name: Z,
    /// Description.
    pub description: Z,
    /// History depth.
    pub history_depth: String,
    /// Trash days.
    pub trash_days: String,
}

/// The live rating of a new master password (0010 §4.2, plan 0072): its
/// label and estimated bits, never the password.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct StrengthMeter {
    /// "Weak", "Fair", "Strong" or "Very strong".
    pub label: String,
    /// Whole estimated bits.
    pub bits: u32,
    /// 0 (weak) to 3 (very strong).
    pub level: u8,
}

/// Password guidance.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Guidance {
    /// The password is fair.
    pub fair: bool,
    /// The live rating of the new master password.
    pub meter: Option<StrengthMeter>,
    /// The suggestion.
    pub suggestion: Option<Z>,
}

/// Password and quick unlock.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct PasswordPane {
    /// Quick unlock is available.
    pub quick_available: bool,
    /// The enrolled policy.
    pub policy: Option<QuickPolicy>,
    /// The enrollment belongs to another vault: its name, empty when the
    /// vault list does not have it (the device keeps one, plan 0072).
    pub elsewhere: Option<String>,
    /// Autofill is available.
    pub autofill: bool,
    /// Guidance.
    pub guidance: Guidance,
}

/// The recovery phrase pane.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct PhrasePane {
    /// The shown phrase: words, confirmed, positions.
    pub shown: Option<(Vec<Z>, bool, [usize; 3])>,
}

/// Storage.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Storage {
    /// File size.
    pub file: String,
    /// Free space inside.
    pub free: String,
    /// Kept by snapshots.
    pub snapshots: String,
    /// Free on the device.
    pub disk: String,
    /// Nothing to compact.
    pub empty: bool,
}

/// About this vault.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct About {
    /// Entries, groups, trash, conflicts.
    pub overview: Option<[usize; 4]>,
    /// Vault ID, key generation, format, KDF text.
    pub header: Option<(String, u32, u32, String)>,
    /// App version.
    pub version: String,
}

/// An autofill candidate.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Candidate {
    /// Its key.
    pub key: Ref,
    /// Colour class.
    pub hue: String,
    /// Monogram.
    pub initial: String,
    /// Title.
    pub title: Z,
    /// Username.
    pub username: Z,
    /// Conflicted.
    pub conflicted: bool,
}

/// Autofill.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Autofill {
    /// The request: who receives the values.
    pub label: Option<Z>,
    /// Candidates.
    pub candidates: Vec<Candidate>,
    /// The first page has loaded.
    pub loaded: bool,
    /// Pages.
    pub page: Option<PageNav>,
    /// An app request: package, signers.
    pub app: Option<(String, String)>,
    /// The link search query.
    pub query: Z,
    /// Link results: entry, title.
    pub results: Vec<(Ref, Z)>,
    /// Their pages.
    pub link_page: Option<PageNav>,
}
