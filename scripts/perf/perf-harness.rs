// SPDX-License-Identifier: AGPL-3.0-or-later

//! Disposable public-API performance measurements (plan 0053); see PERF.md.
//! Derived from plan 0048's capacity harness, whose evidence stays unchanged.

use std::io::Write as _;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use qv_core::{
    AnchorDir, CancelToken, Core, CoreConfig, FieldKind, FieldValue, ItemHandle, MasterPassword,
    PageLimit,
};
use zeroize::Zeroizing;

type R<T> = Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &[u8] = b"performance measurement synthetic password, not personal data";

fn memory(name: &str) -> R<u64> {
    std::fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|value| value.split_whitespace().next()?.parse().ok())
        .ok_or_else(|| "missing process memory counter".into())
}

fn observe<T>(stage: &str, operation: impl FnOnce() -> R<T>) -> R<T> {
    let before = memory("VmRSS:")?;
    let peak = AtomicU64::new(before);
    let done = AtomicBool::new(false);
    let start = Instant::now();
    let result = std::thread::scope(|scope| {
        let sampler = scope.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                if let Ok(rss) = memory("VmRSS:") {
                    peak.fetch_max(rss, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        let result = operation();
        done.store(true, Ordering::Relaxed);
        sampler.join().map_err(|_| "sampler failed")?;
        result
    });
    let after = memory("VmRSS:")?;
    peak.fetch_max(after, Ordering::Relaxed);
    println!(
        "{stage},{:.3},{before},{after},{},{}",
        start.elapsed().as_secs_f64() * 1000.0,
        peak.load(Ordering::Relaxed),
        memory("VmHWM:")?
    );
    std::io::stdout().flush()?;
    result
}

fn run() -> R<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: perf-harness generate DIR ROWS | sample DIR search|fieldsearch|refine|kinds|batch|recursive"
                .into(),
        );
    }
    let dir = Path::new(&args[1]);
    let password = MasterPassword::from_utf8(PASSWORD)?;
    if args[0] == "generate" {
        let rows: usize = args[2].parse()?;
        if !(1..=180).contains(&rows) || dir.exists() {
            return Err("use a new private directory and 1..=180 rows".into());
        }
        std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.join("anchors"))?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.join("vault"))?;
        let core = Core::new(CoreConfig::new(AnchorDir::open(&dir.join("anchors"))?));
        let created = core.create(&dir.join("vault/v.qvault"), &password, "Capacity")?;
        let session = created.session;
        drop(created.recovery_phrase);
        let group = session.save_group(session.new_group(session.root()?, "bulk")?)?;
        let value = Zeroizing::new("x".repeat(256 * 1024));
        for n in 0..rows {
            let mut draft = session.new_entry(group, "login", &format!("bulk {n:03}"))?;
            for name in ["Username", "Website text", "Other text"] {
                draft.add_field(name, FieldKind::Text, FieldValue::text(&value)?)?;
            }
            session.save_entry(draft)?;
        }
        if session.overview()?.entries != rows || !session.verify(None)?.ok() {
            return Err("generated fixture failed verification".into());
        }
        session.lock();
        println!("generated,{rows},{}", rows * 3 * 256 * 1024);
        return Ok(());
    }
    if args[0] != "sample" {
        return Err("unknown command".into());
    }
    let core = Core::new(CoreConfig::new(AnchorDir::open(&dir.join("anchors"))?));
    println!("stage,elapsed_ms,before_rss_kib,after_rss_kib,sampled_peak_rss_kib,process_hwm_kib");
    let session = observe("unlock", || {
        Ok(core.unlock(&dir.join("vault/v.qvault"), &password, None)?)
    })?;
    let count = session.overview()?.entries;
    let cancel = CancelToken::new();
    let handles = observe("traverse", || {
        let mut handles = Vec::new();
        let mut cursor = None;
        loop {
            let page = session.all_items_page(cursor, PageLimit::default(), &cancel)?;
            handles.extend(page.items.into_iter().map(|item| item.handle));
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        if handles.len() != count || count == 0 {
            return Err("incomplete paged traversal".into());
        }
        Ok(handles)
    })?;
    let before = session.view_revision()?;
    observe(&args[2], || {
        match args[2].as_str() {
            "fieldsearch" => {
                // No title or group matches: every searchable field is examined.
                let page = session.search_page("xy", None, PageLimit::default(), &cancel)?;
                if !page.items.is_empty() || page.next.is_some() {
                    return Err("field search unexpectedly matched".into());
                }
            }
            "kinds" => {
                let page = session.kinds_page(None, PageLimit::default(), &cancel)?;
                if page.items.iter().map(|k| k.count).sum::<usize>() != count {
                    return Err("kind count mismatch".into());
                }
            }
            "refine" => {
                // Typing ahead: first page of each prefix, then all pages of the last.
                for query in ["b", "bu", "bul"] {
                    session.search_page(query, None, PageLimit::default(), &cancel)?;
                }
                let mut cursor = None;
                let mut hits = 0;
                loop {
                    let page =
                        session.search_page("bulk", cursor, PageLimit::default(), &cancel)?;
                    hits += page
                        .items
                        .iter()
                        .filter(|hit| matches!(hit, qv_core::SearchHit::Entry(_)))
                        .count();
                    cursor = page.next;
                    if cursor.is_none() {
                        break;
                    }
                }
                if hits != count {
                    return Err("refined search count mismatch".into());
                }
            }
            "batch" => session.set_entry_icons(&handles, Some("blue"))?,
            "recursive" => {
                let groups = session.groups_page(
                    Some(session.root()?),
                    "bulk",
                    None,
                    PageLimit::default(),
                    &cancel,
                )?;
                if groups.items.len() != 1 || groups.next.is_some() {
                    return Err("expected exactly one bulk group".into());
                }
                session.delete(ItemHandle::Group(groups.items[0].handle), true)?;
                let overview = session.overview()?;
                if overview.entries != 0 || overview.in_trash != count + 1 {
                    return Err("recursive delete count mismatch".into());
                }
            }
            "search" => {
                let mut cursor = None;
                let mut hits = 0;
                loop {
                    let page =
                        session.search_page("bulk", cursor, PageLimit::default(), &cancel)?;
                    hits += page
                        .items
                        .iter()
                        .filter(|hit| matches!(hit, qv_core::SearchHit::Entry(_)))
                        .count();
                    cursor = page.next;
                    if cursor.is_none() {
                        break;
                    }
                }
                if hits != count {
                    return Err("search count mismatch".into());
                }
            }
            _ => return Err("unknown operation".into()),
        }
        Ok(())
    })?;
    let expected = before + u64::from(matches!(args[2].as_str(), "batch" | "recursive"));
    if session.view_revision()? != expected || !session.verify(None)?.ok() {
        return Err("unexpected commit count or failed integrity check".into());
    }
    session.lock();
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("capacity-harness: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
