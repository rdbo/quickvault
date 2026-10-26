// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault info [--full]` (spec 0011 §4, §1.4).
//!
//! Without `--full`, no password is asked: the header is read but not
//! authenticated, and the output says so. `--full` unlocks (verifying the
//! whole vault and its anchor) and adds the name, the counts and the last
//! change.

use clap::ArgMatches;
use qv_core::{Overview, VaultInfo};

use crate::cli::Ctx;
use crate::exit::CliError;
use crate::json::Json;
use crate::out::{Out, rfc3339};

pub(crate) fn run(ctx: &Ctx, m: &ArgMatches) -> Result<(), CliError> {
    let path = ctx.vault_path()?;
    let core = crate::select::core()?;
    let info = core.inspect(&path)?;
    crate::cli::warn_location(info.warnings);
    let overview = if m.get_flag("full") {
        let session = ctx.unlock_path(&path)?;
        let o = session.overview()?;
        session.lock();
        Some(o)
    } else {
        None
    };
    let mut out = Out::stdout();
    if ctx.json {
        json(&mut out, &info, overview.as_ref());
    } else {
        human(&mut out, &info, overview.as_ref());
    }
    out.flush()
}

fn human(o: &mut Out, i: &VaultInfo, overview: Option<&Overview>) {
    o.raw("Vault header (unverified: not authenticated without the password)\n");
    o.raw(&format!("  vault id:        {}\n", i.vault_id));
    o.raw(&format!("  format:          {:#010x}", i.schema_version));
    if i.schema_version >> 16 == 0x7fff {
        o.raw(" (development; no compatibility promise)");
    }
    o.raw("\n");
    o.raw(&format!("  key generation:  {}\n", i.key_generation));
    o.raw(&format!(
        "  profiles:        stored-data {}, derivation {}, MAC {} (minimum stored-data {}, derivation {})\n",
        i.data_profile, i.derivation_profile, i.mac_profile, i.min_data_profile, i.min_derivation_profile
    ));
    o.raw(&format!(
        "  password KDF:    profile {}: Argon2id, {} MiB, {} iterations, {} lanes\n",
        i.kdf_profile,
        i.kdf.memory_kib / 1024,
        i.kdf.iterations,
        i.kdf.parallelism
    ));
    if let Some(v) = overview {
        o.raw("Vault contents (verified)\n");
        o.raw("  name:            ").text(v.name.expose()).raw("\n");
        o.raw(&format!("  entries:         {}\n", v.entries));
        o.raw(&format!("  groups:          {}\n", v.groups));
        o.raw(&format!("  in trash:        {}\n", v.in_trash));
        o.raw(&format!("  conflicts:       {}\n", v.conflicts));
        if let Some(t) = v.last_modified {
            o.raw(&format!("  last change:     {}\n", rfc3339(t.0)));
        }
    }
}

fn json(o: &mut Out, i: &VaultInfo, overview: Option<&Overview>) {
    let mut j = Json::new(o);
    j.begin_obj();
    j.key("verified").bool(false);
    j.key("vault_id").str(&i.vault_id);
    j.key("schema_version").uint(u64::from(i.schema_version));
    j.key("key_generation").uint(u64::from(i.key_generation));
    j.key("profiles").begin_obj();
    j.key("data").uint(u64::from(i.data_profile));
    j.key("derivation").uint(u64::from(i.derivation_profile));
    j.key("mac").uint(u64::from(i.mac_profile));
    j.key("min_data").uint(u64::from(i.min_data_profile));
    j.key("min_derivation")
        .uint(u64::from(i.min_derivation_profile));
    j.end_obj();
    j.key("kdf").begin_obj();
    j.key("profile").uint(u64::from(i.kdf_profile));
    j.key("memory_kib").uint(u64::from(i.kdf.memory_kib));
    j.key("iterations").uint(u64::from(i.kdf.iterations));
    j.key("parallelism").uint(u64::from(i.kdf.parallelism));
    j.end_obj();
    if let Some(v) = overview {
        j.key("overview").begin_obj();
        j.key("name").str(v.name.expose());
        j.key("entries").uint(v.entries as u64);
        j.key("groups").uint(v.groups as u64);
        j.key("in_trash").uint(v.in_trash as u64);
        j.key("conflicts").uint(v.conflicts as u64);
        j.key("last_modified").time(v.last_modified.map(|t| t.0));
        j.end_obj();
    }
    j.end_obj();
    o.raw("\n");
}
