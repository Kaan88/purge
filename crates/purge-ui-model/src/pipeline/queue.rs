//! The programs ticked for one "Uninstall N" click (the port of `ui/Purge.Client/Pipeline/UninstallQueue.cs`),
//! run one after another through the Uninstall pipeline. Each keeps its own confirmation, prompts and
//! leftover step; the next one starts only when the user asks for it on the Uninstall page, after the
//! current one finished or was given up, or it is skipped.

use std::collections::HashSet;

use super::UninstallTarget;

/// The queue of one click.
#[derive(Debug, Clone, Default)]
pub struct UninstallQueue {
    targets: Vec<UninstallTarget>,
    index: Option<usize>,
}

impl UninstallQueue {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// The program the pipeline runs now; `None` when the queue is empty.
    pub fn current(&self) -> Option<&UninstallTarget> {
        self.index.and_then(|i| self.targets.get(i))
    }

    /// The program that follows [`Self::current`]; `None` at the last one.
    pub fn next(&self) -> Option<&UninstallTarget> {
        self.index.and_then(|i| self.targets.get(i + 1))
    }

    /// How many programs the click queued (skipped ones are no longer counted).
    pub fn count(&self) -> usize {
        self.targets.len()
    }

    /// The 1-based place of [`Self::current`]; 0 when the queue is empty.
    pub fn position(&self) -> usize {
        match (self.current(), self.index) {
            (Some(_), Some(i)) => i + 1,
            _ => 0,
        }
    }

    /// True when more than one program was queued: the page says "2 of 3".
    pub fn is_batch(&self) -> bool {
        self.targets.len() > 1
    }

    /// "2 of 3" for a batch, `None` for a single program.
    pub fn position_text(&self) -> Option<String> {
        (self.is_batch() && self.current().is_some())
            .then(|| format!("{} of {}", self.position(), self.count()))
    }

    /// Starts a new queue (a program listed twice runs once) and returns its first program; `None` when empty.
    pub fn start(
        &mut self,
        targets: impl IntoIterator<Item = UninstallTarget>,
    ) -> Option<&UninstallTarget> {
        self.targets.clear();
        let mut seen = HashSet::new();
        self.targets.extend(
            targets
                .into_iter()
                .filter(|t| seen.insert(t.program_id.clone())),
        );
        self.index = (!self.targets.is_empty()).then_some(0);
        self.current()
    }

    /// Moves on to [`Self::next`] and returns it; at the end the queue is empty and this returns `None`.
    pub fn advance(&mut self) -> Option<&UninstallTarget> {
        let i = self.index.filter(|&i| i < self.targets.len())?;
        if i + 1 < self.targets.len() {
            self.index = Some(i + 1);
            return self.current();
        }
        self.clear();
        None
    }

    /// Takes [`Self::next`] out of the queue without running it; returns the skipped program.
    pub fn skip_next(&mut self) -> Option<UninstallTarget> {
        self.next()?;
        let i = self.index? + 1;
        Some(self.targets.remove(i))
    }

    /// Forgets the queue.
    pub fn clear(&mut self) {
        self.targets.clear();
        self.index = None;
    }
}

#[cfg(test)]
mod tests {
    //! The queue part of `ui/Purge.Client.Tests/UninstallQueueTests.cs` (the column part is in
    //! `programs::tests`).

    use super::*;

    fn t(key: &str, name: &str) -> UninstallTarget {
        UninstallTarget::new(format!("HKLM|64|{key}").parse().expect("id"), name)
    }

    #[test]
    fn three_ticked_programs_run_in_order_and_say_where_they_are() {
        let (a, b, c) = (t("A", "Alpha"), t("B", "Beta"), t("C", "Gamma"));
        let mut queue = UninstallQueue::new();

        assert_eq!(queue.start([a.clone(), b.clone(), c.clone()]), Some(&a));
        assert_eq!(queue.position_text().as_deref(), Some("1 of 3"));
        assert_eq!(queue.next(), Some(&b));

        assert_eq!(queue.advance(), Some(&b));
        assert_eq!(queue.position_text().as_deref(), Some("2 of 3"));
        assert_eq!(queue.next(), Some(&c));

        assert_eq!(queue.advance(), Some(&c));
        assert_eq!(queue.position_text().as_deref(), Some("3 of 3"));
        assert_eq!(queue.next(), None);

        assert_eq!(queue.advance(), None);
        assert_eq!(queue.current(), None);
        assert_eq!(queue.count(), 0);
    }

    #[test]
    fn a_skipped_program_is_not_run_and_no_longer_counted() {
        let (a, b, c) = (t("A", "Alpha"), t("B", "Beta"), t("C", "Gamma"));
        let mut queue = UninstallQueue::new();
        queue.start([a, b.clone(), c.clone()]);

        assert_eq!(queue.skip_next(), Some(b));

        assert_eq!(queue.next(), Some(&c));
        assert_eq!(queue.position_text().as_deref(), Some("1 of 2"));
        assert_eq!(queue.advance(), Some(&c));
        assert_eq!(queue.skip_next(), None);
    }

    #[test]
    fn one_program_is_no_batch_and_a_repeated_one_runs_once() {
        let (a, b) = (t("A", "Alpha"), t("B", "Beta"));
        let mut queue = UninstallQueue::new();

        queue.start([a.clone()]);
        assert!(!queue.is_batch());
        assert_eq!(queue.position_text(), None);
        assert_eq!(queue.next(), None);

        queue.start([a.clone(), a, b]);
        assert_eq!(queue.count(), 2);
        assert_eq!(UninstallQueue::new().start([]), None);
    }

    #[test]
    fn a_new_click_replaces_the_queue() {
        let mut queue = UninstallQueue::new();
        queue.start([t("A", "Alpha"), t("B", "Beta")]);
        let c = t("C", "Gamma");
        queue.start([c.clone()]);

        assert_eq!(queue.current(), Some(&c));
        assert_eq!(queue.next(), None);
    }
}
