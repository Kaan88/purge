//! The toolkit dialog as UI Automation sees it: an AccessKit tree built from the same sheet, layout
//! and state the frame was drawn from.
//!
//! | AutomationId | Control type | Name | Patterns |
//! |---|---|---|---|
//! | (the window) | Window | the title, "Purge security prompt" | |
//! | `ConsentInstruction` | Text | the main instruction | |
//! | `ConsentList` | List | "Details" | |
//! | `ConsentLine_<n>` | ListItem | line `n` of the list (0 is the first): a summary line, a heading, an attention entry, another item | |
//! | `ConsentVerify` | CheckBox | the verification text | Toggle |
//! | `ConsentFooter` | Text | the footer, which holds "Code XXXX-XXXX" | |
//! | `ConsentHint` | Text | why the button is disabled, while it says so | |
//! | `ConsentApprove` | Button | the label of the button that approves | Invoke, while enabled |
//! | `ConsentCancel` | Button | "Cancel" | Invoke |
//! | `ConsentClose` | Button | "Close" | Invoke |
//!
//! Every line of the list is in the tree, in view or not, so a reader reads the whole list and a
//! client finds any entry by its id; a line out of view has no rectangle. The box and the buttons
//! take Invoke and Toggle like a click, through the same [`Prompt::press`], with the same rules: a
//! disabled button is told as disabled and has no Invoke. The keyboard's place is the tree's focus.
//!
//! Windows adds its own elements for the window's frame beside these, as for any top-level window
//! (seen with the preview): a TitleBar, the system menu (`SystemMenuBar`) and the buttons `Minimize`,
//! `Maximize` and `Close`. Its `Close` is the window's close request, which is Cancel.
//!
//! The provider lives in the elevated broker, so a client below its integrity level gets nothing
//! from it: that is User Interface Privilege Isolation's doing, not this module's, and the VM mode
//! `m3-consent` is what checks it.
//!
//! [`Prompt::press`]: super::state::Prompt::press

use std::time::Instant;

use mdshared_ui::a11y::accesskit::{Node, NodeId};
use mdshared_ui::a11y::{self, Item, Tree};

use super::draw::{CANCEL, CLOSE, Layout, Metrics, hint};
use super::state::{Ctl, Prompt};

/// The name of the list.
pub const LIST_NAME: &str = "Details";

/// The AutomationId of the main instruction.
pub const INSTRUCTION: &str = "ConsentInstruction";
/// The AutomationId of the list.
pub const LIST: &str = "ConsentList";
/// The AutomationId of the verification box.
pub const VERIFY: &str = "ConsentVerify";
/// The AutomationId of the footer.
pub const FOOTER: &str = "ConsentFooter";
/// The AutomationId of the hint beside the disabled button.
pub const HINT: &str = "ConsentHint";
/// The AutomationId of the button that approves.
pub const APPROVE: &str = "ConsentApprove";
/// The AutomationId of Cancel.
pub const CANCEL_ID: &str = "ConsentCancel";
/// The AutomationId of the close box.
pub const CLOSE_ID: &str = "ConsentClose";

/// The AutomationId of line `n` of the list.
pub fn line_id(n: usize) -> String {
    format!("ConsentLine_{n}")
}

/// The AutomationId of a control.
pub fn author(ctl: Ctl) -> &'static str {
    match ctl {
        Ctl::Verify => VERIFY,
        Ctl::Approve => APPROVE,
        Ctl::Cancel => CANCEL_ID,
        Ctl::Close => CLOSE_ID,
    }
}

/// The control a node is, if it is one.
pub fn ctl_of(node: NodeId) -> Option<Ctl> {
    [Ctl::Verify, Ctl::Approve, Ctl::Cancel, Ctl::Close]
        .into_iter()
        .find(|c| a11y::id(author(*c)) == node)
}

fn put(tree: &mut Tree, children: &mut Vec<NodeId>, author: &str, node: Node) {
    let id = a11y::id(author);
    tree.add(id, node);
    children.push(id);
}

/// Adds the dialog's nodes under the tree's root and answers the node with the keyboard.
pub fn build(
    tree: &mut Tree,
    scale: f32,
    prompt: &Prompt,
    m: &Metrics,
    lay: &Layout,
    now: Instant,
) -> NodeId {
    let sheet = prompt.sheet();
    let mut children = Vec::with_capacity(8);
    put(
        tree,
        &mut children,
        INSTRUCTION,
        a11y::text(&sheet.instruction, INSTRUCTION, lay.header),
    );
    let list = a11y::plain_list(
        tree,
        LIST_NAME,
        LIST,
        Some(lay.body),
        sheet.blocks.iter().enumerate().map(|(i, block)| Item {
            key: i,
            label: block.text().to_owned(),
            author: line_id(i),
            bounds: lay.row_in_view(m, i),
        }),
    );
    children.push(list);
    if let (Some(text), Some(r)) = (&sheet.verification, lay.verify_hit()) {
        let node = a11y::check_box(text, VERIFY, r, Some(prompt.ticked()), false);
        put(tree, &mut children, VERIFY, node);
    }
    put(
        tree,
        &mut children,
        FOOTER,
        a11y::text(&sheet.footer, FOOTER, lay.footer),
    );
    if let Some(text) = hint(prompt, now) {
        put(
            tree,
            &mut children,
            HINT,
            a11y::text(text, HINT, lay.footer),
        );
    }
    let approve = a11y::button(
        &sheet.approve,
        APPROVE,
        lay.approve,
        !prompt.approve_enabled(now),
    );
    put(tree, &mut children, APPROVE, approve);
    let cancel = a11y::button(CANCEL, CANCEL_ID, lay.cancel, false);
    put(tree, &mut children, CANCEL_ID, cancel);
    let close = a11y::button(CLOSE, CLOSE_ID, lay.close, false);
    put(tree, &mut children, CLOSE_ID, close);
    let root = tree.root();
    tree.add(root, a11y::window(&sheet.title, scale, children));
    a11y::id(author(prompt.focus()))
}

/// The tree of a window that shows no dialog: the root alone.
pub fn build_empty(tree: &mut Tree, title: &str, scale: f32) -> NodeId {
    let root = tree.root();
    tree.add(root, a11y::window(title, scale, Vec::new()));
    root
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mdshared_ui::a11y::accesskit::{Action, Role, Toggled, TreeUpdate};
    use mdshared_ui::gfx::{Gfx, Painter};

    use super::super::super::samples;
    use super::super::super::sheet::sheet;
    use super::super::draw::{MAX_HEIGHT, SCROLL_HINT, WIDTH, measure};
    use super::super::state::ARM_DELAY;
    use super::*;

    struct Built {
        update: TreeUpdate,
        focus: NodeId,
    }

    impl Built {
        fn by_id(&self, id: NodeId) -> Option<&Node> {
            self.update
                .nodes
                .iter()
                .find(|(n, _)| *n == id)
                .map(|(_, node)| node)
        }

        /// The node with this AutomationId (not a line of the list).
        fn node(&self, author: &str) -> Option<&Node> {
            self.by_id(a11y::id(author))
        }

        /// Line `n` of the list: its node id is made from the list's and its place.
        fn line(&self, n: usize) -> &Node {
            self.by_id(a11y::item_id(a11y::id(LIST), n))
                .unwrap_or_else(|| panic!("line {n} is in the tree"))
        }
    }

    fn built(name: &str, setup: impl FnOnce(&mut Prompt, Instant), scroll: f32) -> (Built, Prompt) {
        let all = samples::all();
        let sample = all.iter().find(|s| s.name == name).unwrap();
        let sh = Arc::new(sheet(&sample.view));
        let mut gfx = Gfx::new();
        let mut scratch = mdshared_text::Bitmap::new(1, 1);
        let m = measure(
            &mut Painter::new(&mut scratch, &mut gfx, 1.0),
            &sh,
            WIDTH,
            1.0,
        );
        let lay = Layout::new(&m, (WIDTH, m.window_height(MAX_HEIGHT)), scroll);
        let mut prompt = Prompt::new(sh);
        let t0 = Instant::now();
        prompt.opened(t0);
        if lay.end_in_view() {
            prompt.saw_end();
        }
        let now = t0 + ARM_DELAY;
        setup(&mut prompt, now);
        let mut tree = Tree::new(a11y::id("root"));
        tree.begin();
        let focus = build(&mut tree, 1.25, &prompt, &m, &lay, now);
        let update = tree.end(focus);
        (Built { update, focus }, prompt)
    }

    #[test]
    fn the_tree_names_every_part_by_its_id() {
        let (b, prompt) = built("quarantine", |_, _| {}, 0.0);
        let sh = prompt.sheet();
        let instruction = b.node(INSTRUCTION).unwrap();
        assert_eq!(instruction.role(), Role::Label);
        assert_eq!(instruction.value(), Some(sh.instruction.as_str()));
        let list = b.node(LIST).unwrap();
        assert_eq!(list.label(), Some(LIST_NAME));
        assert_eq!(list.children().len(), sh.blocks.len());
        for (i, block) in sh.blocks.iter().enumerate() {
            let line = b.line(i);
            assert_eq!(line.label(), Some(block.text()), "line {i}");
            assert_eq!(line.author_id(), Some(line_id(i).as_str()));
            assert!(!line.supports_action(Action::Click), "a line takes nothing");
        }
        let footer = b.node(FOOTER).unwrap();
        assert!(footer.value().unwrap().contains("Code "));
        let verify = b.node(VERIFY).unwrap();
        assert_eq!(verify.role(), Role::CheckBox);
        assert_eq!(verify.toggled(), Some(Toggled::False));
        assert_eq!(verify.label(), sh.verification.as_deref());
        assert!(verify.supports_action(Action::Click));
        let cancel = b.node(CANCEL_ID).unwrap();
        assert_eq!(
            (cancel.role(), cancel.label()),
            (Role::Button, Some(CANCEL))
        );
        assert!(cancel.supports_action(Action::Click));
        assert_eq!(b.node(CLOSE_ID).unwrap().label(), Some(CLOSE));
        // Cancel has the keyboard when the dialog opens.
        assert_eq!(b.focus, a11y::id(CANCEL_ID));
        assert_eq!(ctl_of(b.focus), Some(Ctl::Cancel));
        assert_eq!(ctl_of(a11y::id(LIST)), None);
    }

    #[test]
    fn the_button_is_told_disabled_until_it_can_be_pressed() {
        // The box is not ticked: disabled, and no Invoke.
        let (b, prompt) = built("quarantine", |_, _| {}, 0.0);
        let approve = b.node(APPROVE).unwrap();
        assert_eq!(approve.label(), Some(prompt.sheet().approve.as_str()));
        assert!(approve.is_disabled());
        assert!(!approve.supports_action(Action::Click));
        // Ticked, armed, the list at its end: enabled, with Invoke.
        let (b, _) = built(
            "quarantine",
            |p, now| {
                p.press(Ctl::Verify, now);
            },
            f32::MAX,
        );
        let approve = b.node(APPROVE).unwrap();
        assert!(!approve.is_disabled());
        assert!(approve.supports_action(Action::Click));
        assert_eq!(b.node(VERIFY).unwrap().toggled(), Some(Toggled::True));
        assert!(b.node(HINT).is_none());
        // No box at all on a dialog without attention entries.
        let (b, _) = built("quarantine-plain", |_, _| {}, 0.0);
        assert!(b.node(VERIFY).is_none());
        assert!(!b.node(APPROVE).unwrap().is_disabled());
    }

    #[test]
    fn a_long_list_is_whole_in_the_tree_and_only_the_lines_in_view_have_a_place() {
        let (b, prompt) = built("quarantine-long", |_, _| {}, 0.0);
        let n = prompt.sheet().blocks.len();
        assert!(n > 200);
        assert!(b.line(0).bounds().is_some());
        let last = b.line(n - 1);
        assert!(last.bounds().is_none(), "out of view");
        assert!(last.label().unwrap().contains("Profile 0199"));
        // The end has not been on screen: the button is disabled and the hint says why.
        assert!(b.node(APPROVE).unwrap().is_disabled());
        assert_eq!(b.node(HINT).unwrap().value(), Some(SCROLL_HINT));
    }
}
