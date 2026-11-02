// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared responsive screens. Vault text is rendered as escaped text only.
mod workspace;
use crate::controller::{Action, AppError, Controller, FormEpoch, InputField, Mode, Phase};
use dioxus::prelude::*;
use std::sync::OnceLock;

pub(crate) static ACTIVE: OnceLock<Result<Controller, crate::controller::AppError>> =
    OnceLock::new();

pub(crate) fn app() -> Element {
    let mut changed = use_signal_sync(|| 0u64);
    use_hook(move || {
        std::thread::spawn(move || {
            let mut previous = None;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
                // Async startup failures must refresh the screen too.
                let snapshot = ACTIVE.get().map(|result| {
                    result
                        .as_ref()
                        .map(Controller::snapshot)
                        .map_err(|error| *error)
                });
                if previous != snapshot {
                    previous = snapshot;
                    if let Ok(mut value) = changed.try_write() {
                        *value = value.wrapping_add(1);
                    }
                }
            }
        });
    });
    let revision = *changed.read();
    match ACTIVE.get() {
        Some(Ok(controller)) => rsx! { Screen {controller:controller.clone(),revision} },
        _ => {
            let error = ACTIVE
                .get()
                .and_then(|r| r.as_ref().err())
                .copied()
                .unwrap_or(AppError::Unavailable);
            let title = match error {
                AppError::LockMonitoring => "Lock monitoring unavailable",
                AppError::PrivateStorage => "Private storage unavailable",
                AppError::AlreadyRunning => "QuickVault is already running",
                _ => "Protection unavailable",
            };
            let message = error.message();
            rsx! {main {class:"shell", Header{} section {class:"card", h1{"{title}"} p{"{message}"} p{class:"muted","No vault has been opened by this window."}}}}
        }
    }
}
/// Synthetic flow result handler; a no-op outside validation builds.
#[cfg(feature = "validation")]
fn fixture_report(controller: &Controller) -> impl FnMut(FormEvent) + 'static {
    let c = controller.clone();
    move |event: FormEvent| {
        let value = event.value();
        if let Some(stage) = value
            .strip_prefix("FAIL:")
            .and_then(|n| n.parse::<u8>().ok())
        {
            eprintln!("synthetic flow stage {stage} failed");
        }
        c.finish_fixture(value == "PASS")
    }
}
#[cfg(not(feature = "validation"))]
fn fixture_report(_: &Controller) -> impl FnMut(FormEvent) + 'static {
    |_| {}
}
#[component]
fn Header() -> Element {
    rsx! {
        header {class:"topbar",div {class:"brand",span {class:"brand-mark","Q"} "QuickVault"} span {class:"offline",span{class:"dot"} "Offline by default"}}
    }
}
#[component]
fn SecretInput(
    controller: Controller,
    epoch: FormEpoch,
    field: InputField,
    label: &'static str,
    id: &'static str,
    secret: bool,
    disabled: bool,
) -> Element {
    rsx! {label {r#for:id,class:"field", span {"{label}"}
        input {id, r#type:if secret{"password"}else{"text"},maxlength:if field==InputField::Path{4096}else{1024},
            disabled,autocomplete:"off",spellcheck:"false",autocapitalize:"off",autocorrect:"off",
            oninput:move|event:FormEvent|{let mut value=event.value();controller.input(epoch,field,&mut value);}
        }
    }}
}
#[component]
fn Screen(controller: Controller, revision: u64) -> Element {
    let _ = revision;
    let mut consent = use_signal(|| (FormEpoch(u64::MAX), false));
    let mut skip_consent = use_signal(|| (FormEpoch(u64::MAX), false));
    #[cfg(feature = "validation")]
    let preview = controller.is_preview();
    #[cfg(not(feature = "validation"))]
    let preview = false;
    #[cfg(feature = "validation")]
    let fixture = controller.is_fixture();
    #[cfg(not(feature = "validation"))]
    let fixture = false;
    let view = controller.snapshot();
    let mode = view.mode;
    let epoch = view.epoch;
    let phase = view.phase;
    let acknowledged = consent().0 == epoch && consent().1;
    let skip_acknowledged = skip_consent().0 == epoch && skip_consent().1;
    let os = controller.protection();
    let protection = qv_core::harden();
    let error = view.error;
    let status = view.status;
    let phrase = controller.phrase(epoch);
    let phrase_text = phrase
        .as_ref()
        .and_then(|v| std::str::from_utf8(v.expose_secret()).ok())
        .unwrap_or("");
    let suggestion = controller.suggestion(epoch);
    let suggestion_text = suggestion
        .as_ref()
        .and_then(|v| std::str::from_utf8(v.expose_secret()).ok())
        .unwrap_or("");
    let invoke = |action| {
        let controller = controller.clone();
        move |_| controller.perform(epoch, action, acknowledged)
    };
    if phase == Phase::Unlocked {
        return rsx! {
            workspace::Shell {
                controller: controller.clone(),
                epoch,
                revision: view.revision,
                live: view.live,
                busy: view.busy,
                reduced_lifecycle: view.reduced_lifecycle,
                fixture,
                on_fixture: fixture_report(&controller),
            }
        };
    }
    let resume = view.resume;
    let over_budget = view.over_budget;
    let rotation_confirmed = view.rotation_confirmed;
    rsx! {
        main {class:"shell", "data-qv-epoch":"{epoch.0}", Header{}
            if fixture && cfg!(target_os="android") {p {class:"warning","Synthetic validation build · isolated test vault only"}}
            if preview {p {class:"hint","Read-only preview · vault actions are disabled. Do not enter real credentials."}}
            div {class:"layout",
                aside {class:"intro",
                    span {class:"eyebrow","YOUR SECRETS, YOUR DEVICE"}
                    h1 {"A quieter place" br{} "for your passwords."}
                    p {class:"lead","Your vault stays encrypted on this device. No account, server, or internet connection is needed."}
                    div {class:"principles",
                        div {span {class:"principle-icon","01"} div {strong {"Local first"} p {"Open your vault wherever you are."}}}
                        div {span {class:"principle-icon","02"} div {strong {"Keys stay with you"} p {"Your password or recovery phrase opens your vault."}}}
                        div {span {class:"principle-icon","03"} div {strong {"A clear lock boundary"} p {"Locking clears app state and cancels pending work."}}}
                    }
                    div {class:"security-note", "Framework and OS copies have best-effort cleanup. Device storage, swap, and hibernation protection depend on the OS."}
                }
                section {class:"card",key:"screen-{epoch.0}",
                    div {class:"card-heading",span{class:"eyebrow","YOUR PRIVATE VAULT"} span {class:"status-pill", "{status}"}}
                    if view.reduced_lifecycle {
                        p {class:"warning",role:"status","Automatic locking on screen lock or sleep is unavailable. Manual lock and the 60-second inactivity lock remain active."}
                    }
                    if phase == Phase::Locked && let Some(need) = resume {
                        h2 {"Finish the interrupted key rotation"}
                        p {class:"muted","A key rotation for this vault was interrupted. Complete it to use the new master password and phrase, or roll it back to keep the previous ones. Nothing else can open the vault until it is finished."}
                        if need.new {
                            SecretInput{controller:controller.clone(),epoch,field:InputField::Password,label:"New master password (chosen for the rotation)",id:"resume-new",secret:true,disabled:view.busy}
                        }
                        if need.old {
                            SecretInput{controller:controller.clone(),epoch,field:InputField::Repeat,label:"Previous master password",id:"resume-old",secret:true,disabled:view.busy}
                        }
                        button {class:"primary","data-qv-clear":"true",disabled:view.busy,onclick:invoke(Action::ResumeComplete),"Complete the rotation" span{"→"}}
                        button {class:"secondary","data-qv-clear":"true",disabled:view.busy,onclick:invoke(Action::ResumeRollback),"Roll back to the previous generation"}
                        button {class:"text-button","data-qv-clear":"true",onclick:{let c=controller.clone();move |_|c.lock()},"Cancel"}
                    }else if phase==Phase::Rotation{
                        h2 {"Your new recovery phrase"}
                        p {class:"muted","Write these 24 words down in order. They replace the old phrase once the rotation is installed. Nothing has changed yet."}
                        div {class:"phrase", "{phrase_text}"}
                        if rotation_confirmed {
                            p {class:"notice","The new recovery words are confirmed."}
                            button {class:"primary","data-qv-clear":"true",disabled:view.busy,onclick:invoke(Action::InstallRotation),if view.busy{"Installing…"}else{"Install the key rotation"} span{"→"}}
                        }else{
                            p {"Confirm the requested words to continue."}
                            for (field,id,label) in [(InputField::Word0,"rot-word-0","First requested word"),(InputField::Word1,"rot-word-1","Second requested word"),(InputField::Word2,"rot-word-2","Third requested word")] {
                                SecretInput{controller:controller.clone(),epoch,field,label,id,secret:true,disabled:view.busy}
                            }
                            p {class:"hint","Word positions: {view.positions[0]}, {view.positions[1]}, {view.positions[2]}"}
                            button {class:"primary","data-qv-clear":"true",disabled:view.busy,onclick:invoke(Action::ConfirmRotation),"Confirm recovery words"}
                        }
                        button {class:"text-button","data-qv-clear":"true",disabled:view.busy,onclick:invoke(Action::CancelRotation),"Cancel the rotation (nothing changes)"}
                    }else if matches!(phase,Phase::Locked|Phase::Opening|Phase::WeakPassword){
                        h2 {if mode==Mode::Unlock{"Welcome back"}else if mode==Mode::Create{"Make yourself a vault"}else{"Recover local access"}}
                        p {class:"muted",if mode==Mode::Unlock{"Unlock a vault already on this device."}else if mode==Mode::Create{"Choose a password, then keep your recovery phrase somewhere safe."}else{"Use your recovery phrase, or explicitly inspect a missing or mismatched local anchor."}}
                        nav {class:"tabs","aria-label":"Vault action",
                            for (n,label) in [(Mode::Unlock,"Unlock"),(Mode::Create,"Create"),(Mode::Recover,"Recover")] {
                                button {class:if mode==n{"selected"}else{""},disabled:view.busy,onclick:{let c=controller.clone();move |_|{c.select_mode(epoch,n);}},"{label}"}
                            }
                        }
                        SecretInput{controller:controller.clone(),epoch,field:InputField::Path,label:"Vault file path (blank uses the app vault)",id:"vault-path",secret:false,disabled:view.busy}
                        if mode==Mode::Create{
                            SecretInput{controller:controller.clone(),epoch,field:InputField::Name,label:"Vault name",id:"vault-name",secret:false,disabled:view.busy}
                        }
                        if mode!=Mode::Recover{
                            SecretInput{controller:controller.clone(),epoch,field:InputField::Password,label:"Master password",id:"password",secret:true,disabled:view.busy}
                        }else{
                            SecretInput{controller:controller.clone(),epoch,field:InputField::Phrase,label:"Recovery phrase · 24 words",id:"phrase",secret:true,disabled:view.busy}
                        }
                        if mode==Mode::Create{
                            SecretInput{controller:controller.clone(),epoch,field:InputField::Repeat,label:"Confirm master password",id:"repeat",secret:true,disabled:view.busy}
                            p {class:"hint","Consider a generated six-word passphrase. Longer, unpredictable passwords resist offline guessing."}
                            button {class:"text-button",disabled:view.busy||phase==Phase::WeakPassword||preview,onclick:invoke(Action::SuggestPassword),"Generate a six-word suggestion"}
                            if view.suggestion_visible {div {class:"phrase","{suggestion_text}"} p{class:"hint","Visible for 30 seconds. Write it down, then enter it in both password fields."}}
                        }
                        if view.fair_warning{p {class:"warning","This password is fair. Consider a longer, less predictable passphrase."}}
                        if view.reduced_process {p {class:"warning","Some process or memory-lock protections are unavailable. Protected copies may reach OS storage."}}
                        details {class:"protection",summary{"Device protection status"}
                            p {"Process and memory protection reduced: {protection.is_reduced()}"}
                            p {"Storage: {os.storage:?} · Swap: {os.swap:?} · Hibernation: {os.hibernation:?}"}
                            p {"Lock monitoring: {os.lifecycle} · Clipboard: {os.clipboard}"}
                            p {if os.quick_unlock {"Hardware quick unlock requires explicit enrollment in Settings."} else {"Quick unlock is unavailable on this device."}}
                            p {"Clearing an input cannot guarantee erasure of framework or OS copies."}
                        }
                        label {class:"check",input {r#type:"checkbox",checked:acknowledged,disabled:view.busy,onchange:move|event|consent.set((epoch,event.checked()))} span {"I understand these protection limits and acknowledge reduced protection where shown."}}
                        if phase==Phase::WeakPassword{
                            div {class:"warning",role:"alertdialog","aria-label":"Weak password confirmation", p{"This password is weak and could be guessed by an attacker who obtains your vault file. Create the vault anyway?"}
                                button {class:"secondary",onclick:{let c=controller.clone();move |_|c.select_mode(epoch,Mode::Create)},"Choose a stronger password"}
                                button {disabled:view.weak_seconds>0,onclick:invoke(Action::ConfirmWeak),"Create anyway · {view.weak_seconds}s"}
                            }
                        }else{
                            button {class:"primary","data-qv-clear":"true",disabled:view.busy||!acknowledged||preview,onclick:invoke(if mode==Mode::Create{Action::Create}else if mode==Mode::Recover{Action::Recover}else{Action::Unlock}),
                                if view.busy{"Opening…"}else if mode==Mode::Create{"Create vault"}else if mode==Mode::Recover{"Open with recovery phrase"}else{"Unlock vault"}
                                span {"→"}
                            }
                        }
                        if let Some(banner) = controller.autofill_banner() {
                            p {class:"notice",role:"status","data-qv-autofill":"banner","{banner}"}
                        }
                        if mode==Mode::Unlock && controller.0.services.keystore().binding().is_some() {
                            button { class: "secondary", "data-qv-clear": "true", disabled: view.busy || !acknowledged || preview, onclick: invoke(Action::QuickUnlock), "Quick unlock with the enrolled hardware policy" }
                        }
                        if mode==Mode::Recover{
                            details {summary{"Recover using a password and inspect the local anchor"}
                                SecretInput{controller:controller.clone(),epoch,field:InputField::Password,label:"Master password",id:"recovery-password",secret:true,disabled:view.busy}
                                button {class:"secondary",disabled:view.busy||!acknowledged||preview,onclick:invoke(Action::RecoverPassword),"Inspect for recovery"}
                            }
                        }
                        button {class:"text-button","data-qv-clear":"true",onclick:{let c=controller.clone();move |_|c.lock()},"Cancel and clear"}
                    }else if phase==Phase::Phrase{
                        h2 {"Your recovery phrase"}
                        p {class:"muted","Write these 24 words down in order. Anyone with this phrase and your vault file can open it."}
                        div {class:"phrase", "{phrase_text}"}
                        p {"Confirm the requested words to continue."}
                        for (field,id,label) in [(InputField::Word0,"word-0","First requested word"),(InputField::Word1,"word-1","Second requested word"),(InputField::Word2,"word-2","Third requested word")] {
                            SecretInput{controller:controller.clone(),epoch,field,label,id,secret:true,disabled:view.busy}
                        }
                        p {class:"hint","Word positions: {view.positions[0]}, {view.positions[1]}, {view.positions[2]}"}
                        button {class:"primary","data-qv-clear":"true",disabled:view.busy,onclick:invoke(Action::ConfirmPhrase),"Confirm recovery words"}
                        details {summary{"Skip phrase confirmation"}
                            label {class:"check",input {r#type:"checkbox",checked:skip_acknowledged,onchange:move|event|skip_consent.set((epoch,event.checked()))}span{"I understand I may lose access if I forget my password. Record that I skipped confirmation."}}
                            button {class:"secondary",disabled:view.busy||!skip_acknowledged,onclick:{let c=controller.clone();move |_|c.perform(epoch,Action::SkipPhrase,skip_acknowledged)},"Record skip and continue"}
                        }
                        button {class:"text-button","data-qv-clear":"true",onclick:{let c=controller.clone();move |_|c.lock()},"Lock and clear phrase"}
                    }else if phase==Phase::Recovery{
                        h2 {"Check this recovery baseline"}
                        p {"The external anchor is missing or mismatched. This verified file may be an older copy. Opening it does not prove it is the latest state."}
                        p {"Accepting it first creates a verified recovery snapshot, then establishes a new local baseline. Nothing is adopted without your action."}
                        if let Some(needed) = over_budget {
                            p {class:"warning","The mandatory recovery snapshot needs {needed} bytes and exceeds the snapshot budget."}
                            button {class:"primary","data-qv-clear":"true",disabled:view.busy,onclick:{let c=controller.clone();move |_|c.perform(epoch,Action::AdoptBaselineOverBudget,true)},"Allow the snapshot to exceed the budget and accept"}
                        } else {
                            button {class:"primary","data-qv-clear":"true",disabled:view.busy,onclick:{let c=controller.clone();move |_|c.perform(epoch,Action::AdoptBaseline,true)},"Accept this file as the recovery baseline"}
                        }
                        button {class:"secondary",onclick:{let c=controller.clone();move |_|c.lock()},"Decline and lock"}
                    }else{
                        div {class:"ready-mark","✓"}
                        h2 {"Your vault is open"}
                        p {class:"muted","Your vault is unlocked on this device. Lock it when you step away."}
                        p {class:"hint","The vault locks after 60 seconds of inactivity. Lock it whenever you step away."}
                        button {class:"primary","data-qv-clear":"true",onclick:{let c=controller.clone();move |_|c.lock()},"Lock vault"}
                    }
                    if let Some(error)=error{p {class:"error",role:"alert","{error.message()}"}}
                }
            }
            if fixture {input {id:"validation-result",oninput:fixture_report(&controller)}}
            footer {"QuickVault · encrypted locally · no account required"}
        }
    }
}
