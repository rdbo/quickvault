// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-screen state kept in the backend (plan 0071 decision 3): a page owner
//! per rendered screen part, the last good read per part (no flicker while
//! a new read runs) and a few held values. A slot not used while building a
//! frame is released, as if the part left the screen; a lock clears them all.
use crate::controller::{AppError, Controller, FormEpoch};
use crate::page_read::{Lane, Owner, Read, Spec};
use std::any::Any;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(crate) struct Hooks {
    pages: HashMap<&'static str, Owner>,
    last: HashMap<&'static str, Box<dyn Any + Send>>,
    used: HashSet<&'static str>,
    /// The sidebar's five type counts, kept across popovers (plan 0051).
    pub(crate) counts: Option<[usize; 5]>,
    /// The list shown while a held page is stale (plan 0051).
    pub(crate) shown_list: Option<crate::workspace::Screen>,
}

impl Hooks {
    /// `use_page`: the slot's owner and its current read.
    pub(crate) fn page(
        &mut self,
        c: &Controller,
        epoch: FormEpoch,
        slot: &'static str,
        lane: Lane,
        priority: u8,
        spec: Spec,
    ) -> (Option<Owner>, Option<Read>) {
        self.used.insert(slot);
        let owner = match self.pages.get(slot) {
            Some(o) => Some(*o),
            None => {
                let o = c.page_owner(lane, priority);
                if let Some(o) = o {
                    self.pages.insert(slot, o);
                }
                o
            }
        };
        let read = owner.and_then(|o| c.page(epoch, o, spec));
        (owner, read)
    }

    /// The owner of a rendered slot (page turns).
    pub(crate) fn owner(&self, slot: &str) -> Option<Owner> {
        self.pages
            .iter()
            .find(|(k, _)| **k == slot)
            .map(|(_, o)| *o)
    }

    /// `use_last`: a fresh read, or the slot's last good one while reads are
    /// refused (an operation owns the vault); errors pass through.
    pub(crate) fn last<T: Clone + Send + 'static>(
        &mut self,
        slot: &'static str,
        fresh: Option<Result<T, AppError>>,
    ) -> Option<Result<T, AppError>> {
        self.used.insert(slot);
        match fresh {
            Some(Ok(v)) => {
                self.last.insert(slot, Box::new(v.clone()));
                Some(Ok(v))
            }
            None => self
                .last
                .get(slot)
                .and_then(|b| b.downcast_ref::<T>())
                .cloned()
                .map(Ok),
            other => other,
        }
    }

    /// Ends a frame: releases the slots it did not use.
    pub(crate) fn finish(&mut self, c: &Controller) {
        let used = std::mem::take(&mut self.used);
        let mut released = Vec::new();
        self.pages.retain(|k, o| {
            let keep = used.contains(k);
            if !keep {
                released.push(*o);
            }
            keep
        });
        self.last.retain(|k, _| used.contains(k));
        for o in released {
            c.release_page(o);
        }
    }

    /// On lock: everything goes (the caches hold vault text).
    pub(crate) fn clear(&mut self, c: &Controller) {
        for (_, o) in self.pages.drain() {
            c.release_page(o);
        }
        self.last.clear();
        self.used.clear();
        self.counts = None;
        self.shown_list = None;
    }
}
