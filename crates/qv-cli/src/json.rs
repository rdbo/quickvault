// SPDX-License-Identifier: AGPL-3.0-or-later

//! JSON output (spec 0011 §5.2): a minimal writer into an [`Out`], so vault
//! text never passes through serializer buffers that are not zeroized.
//!
//! Strings use standard JSON escaping; controls, DEL, C1 and the Unicode
//! bidirectional controls are written as `\uXXXX`. Timestamps are RFC 3339
//! UTC strings. A protected value without `--reveal` is `null`, with
//! `"protected": true` beside it.
//!
//! **Schemas** (stable; new keys may be added, existing ones keep their
//! meaning):
//!
//! - `info`: `{"verified": false, "vault_id", "schema_version",
//!   "key_generation", "profiles": {"data", "derivation", "mac",
//!   "min_data", "min_derivation"}, "kdf": {"profile", "memory_kib",
//!   "iterations", "parallelism"}}`; `--full` adds `"overview": {"name",
//!   "entries", "groups", "in_trash", "conflicts", "last_modified"}` (that
//!   part is verified).
//! - `ls`: `{"groups": [{"id", "path", "name"}], "entries": [entry…],
//!   "recovered": [entry…]}` where an entry is `{"id", "path", "title",
//!   "type", "username", "url", "conflict"}`; `username` and `url` are
//!   `null` when absent, `path` is `null` for a recovered entry, and
//!   `recovered` is present when the root is listed.
//! - `search`: `{"hits": [{"kind": "group", "id", "path", "name"} |
//!   {"kind": "entry", "entry": entry}]}`.
//! - `show`: `{"id", "path", "title", "type", "notes", "created",
//!   "modified", "expires", "versions", "fields": [{"name", "kind",
//!   "protected", "value"}]}`; `versions` is the number of conflicting
//!   versions (1 normally); `path` is `null` for a recovered entry. With
//!   `--field`, `{"name", "kind", "protected", "value"}`.
//! - `trash ls`: `{"items": [{"id", "kind", "name", "deleted_at", "conflict"}]}`;
//!   `kind` is `entry` or `group`, `deleted_at` is RFC 3339 or null.
//! - `totp`: `{"code", "seconds_remaining"}`.
//! - `generate`: `{"value", "bits", "strength"}`; `strength` is `weak`,
//!   `fair`, `strong` or `very strong`.

use crate::out::Out;

/// Writes one JSON document into an [`Out`].
pub(crate) struct Json<'a> {
    out: &'a mut Out,
    /// Per open container: whether it has an element yet.
    stack: Vec<bool>,
    /// A key was just written; the next value needs no comma.
    after_key: bool,
}

impl<'a> Json<'a> {
    pub(crate) fn new(out: &'a mut Out) -> Self {
        Self {
            out,
            stack: Vec::new(),
            after_key: false,
        }
    }

    /// Writes a completed portion without losing container/comma state.
    pub(crate) fn flush(&mut self) -> Result<(), crate::exit::CliError> {
        self.out.flush()
    }

    fn sep(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        if let Some(has) = self.stack.last_mut() {
            if *has {
                self.out.raw(",");
            }
            *has = true;
        }
    }

    pub(crate) fn begin_obj(&mut self) -> &mut Self {
        self.sep();
        self.out.raw("{");
        self.stack.push(false);
        self
    }

    pub(crate) fn end_obj(&mut self) -> &mut Self {
        self.stack.pop();
        self.out.raw("}");
        self
    }

    pub(crate) fn begin_arr(&mut self) -> &mut Self {
        self.sep();
        self.out.raw("[");
        self.stack.push(false);
        self
    }

    pub(crate) fn end_arr(&mut self) -> &mut Self {
        self.stack.pop();
        self.out.raw("]");
        self
    }

    /// An object key (program text).
    pub(crate) fn key(&mut self, k: &str) -> &mut Self {
        self.sep();
        self.out.json_str(k.as_bytes());
        self.out.raw(":");
        self.after_key = true;
        self
    }

    /// A string value (vault text).
    pub(crate) fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// A string value from bytes (a field value).
    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.sep();
        self.out.json_str(b);
        self
    }

    pub(crate) fn opt_str(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            Some(s) => self.str(s),
            None => self.null(),
        }
    }

    pub(crate) fn uint(&mut self, n: u64) -> &mut Self {
        self.sep();
        self.out.raw(&n.to_string());
        self
    }

    /// A finite number with one decimal (entropy bits).
    pub(crate) fn bits(&mut self, x: f64) -> &mut Self {
        self.sep();
        let x = if x.is_finite() { x } else { 0.0 };
        self.out.raw(&format!("{x:.1}"));
        self
    }

    pub(crate) fn bool(&mut self, b: bool) -> &mut Self {
        self.sep();
        self.out.raw(if b { "true" } else { "false" });
        self
    }

    pub(crate) fn null(&mut self) -> &mut Self {
        self.sep();
        self.out.raw("null");
        self
    }

    /// An optional timestamp as RFC 3339, or `null`.
    pub(crate) fn time(&mut self, ms: Option<i64>) -> &mut Self {
        match ms {
            Some(ms) => self.str(&crate::out::rfc3339(ms)),
            None => self.null(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_writer_nests_and_separates() {
        let mut o = Out::stdout();
        {
            let mut j = Json::new(&mut o);
            j.begin_obj();
            j.key("a").uint(1);
            j.key("b").begin_arr();
            j.str("x\u{1b}").null().bool(true);
            j.begin_obj().key("t").time(Some(0)).end_obj();
            j.end_arr();
            j.key("c").bits(77.549).key("d").opt_str(None);
            j.end_obj();
        }
        assert_eq!(
            String::from_utf8(o.contents().to_vec()).unwrap(),
            "{\"a\":1,\"b\":[\"x\\u001b\",null,true,{\"t\":\"1970-01-01T00:00:00Z\"}],\"c\":77.5,\"d\":null}"
        );
    }
}
