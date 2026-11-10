// SPDX-License-Identifier: AGPL-3.0-or-later

//! Display paths retain structural IDs only; callers stream one name at a time.
use crate::index::{Data, ViewData};
use crate::session::SessionTag;
use crate::{CoreError, ItemHandle, Session, Text};

/// A snapshot-bound display path. Names are decoded only by `path_next`.
pub struct ViewPath {
    session: SessionTag,
    revision: u64,
    parts: Vec<qv_crypto::RecordId>,
}
impl core::fmt::Debug for ViewPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ViewPath(<redacted>)")
    }
}
impl Session {
    /// Build a path of IDs at `revision`. Returns None for trash/recovered items.
    /// The root has an empty path. Moves and copies do not change this display policy.
    pub fn item_path(
        &self,
        item: ItemHandle,
        revision: u64,
    ) -> Result<Option<ViewPath>, CoreError> {
        self.read(|ctx| {
            if ctx.open.vault.local_seq() != revision {
                return Err(CoreError::StaleHandle);
            }
            let index = &ctx.open.index;
            let (tag, id) = match item {
                ItemHandle::Entry(h) => (h.session, h.record),
                ItemHandle::Group(h) => (h.session, h.record),
            };
            ctx.own(tag)?;
            let info = index.get(id).ok_or(CoreError::NotFound)?;
            if !info.status.live {
                return Ok(None);
            }
            let mut parts = Vec::new();
            let mut group = match &info.data {
                Data::Group(_) if index.tree.parent(id).is_some() => id,
                Data::Entry(e) if index.tree.parent(e.group).is_some() => {
                    parts.push(id);
                    e.group
                }
                _ => return Ok(None),
            };
            while group != index.root {
                ctx.check_cancel()?;
                if parts.len() > index.records.len() {
                    return Err(CoreError::Internal);
                }
                parts.push(group);
                group = index
                    .tree
                    .parent(group)
                    .flatten()
                    .ok_or(CoreError::Internal)?;
            }
            Ok(Some(ViewPath {
                session: ctx.tag(),
                revision,
                parts,
            }))
        })
    }

    /// Read the next root-to-leaf component, without assembling a full path.
    /// Checks the revision even after the final component, so a stale stream fails.
    pub fn path_next(&self, path: &mut ViewPath) -> Result<Option<Text>, CoreError> {
        self.read(|ctx| {
            ctx.own(path.session)?;
            if ctx.open.vault.local_seq() != path.revision {
                return Err(CoreError::StaleHandle);
            }
            let Some(id) = path.parts.last().copied() else {
                return Ok(None);
            };
            let view = ctx.view(id)?;
            let name = match &**view {
                ViewData::Group(g) => &g.name,
                ViewData::Entry(e) => &e.title,
                _ => return Err(CoreError::Internal),
            };
            let name = Text::new(name.expose()).map_err(crate::error::data)?;
            path.parts.pop();
            Ok(Some(name))
        })
    }
}
