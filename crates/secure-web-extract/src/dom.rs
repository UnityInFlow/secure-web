//! A bounded arena DOM built from the [`tokenizer`](crate::tokenizer) stream (ADR-013).
//!
//! html5ever's tree builder (and so `scraper`) is quadratic on hostile input — nested block
//! elements scan the whole open-element stack — so this module builds its own tree:
//!
//! - nodes live in one `Vec` and link by index (no recursion to build, walk or drop);
//! - end tags search at most [`MAX_END_TAG_SCAN`] open elements, implied-end rules at most
//!   [`MAX_IMPLIED_SCAN`], so each token costs O(1) stack work;
//! - the node count is capped at [`MAX_NODES`].
//!
//! It is a simplified HTML tree builder (implied `</p>`, `</li>`, `</td>` … and void elements),
//! not a browser-exact one. Precision only affects `display`; every text node reaches
//! `security_text` whatever tree shape it ends up in.

use crate::tokenizer::{tokenize, Token};

/// Most nodes built per document. A 5 MiB page of `<a>` tags stays below it; hostile pages
/// above it are `CONTENT_TOO_LARGE`.
pub(crate) const MAX_NODES: usize = 1_000_000;

/// Open elements an end tag may search for its match; further-away matches are ignored.
const MAX_END_TAG_SCAN: usize = 128;

/// Open elements an implied-end rule (`<li>` closing `<li>`, …) may search.
const MAX_IMPLIED_SCAN: usize = 16;

/// "No node" link value.
const NONE: u32 = u32::MAX;

/// Node id (index into [`Dom::nodes`]).
pub(crate) type NodeId = u32;

/// The document root.
pub(crate) const ROOT: NodeId = 0;

pub(crate) struct Node {
    pub(crate) parent: u32,
    pub(crate) first_child: u32,
    last_child: u32,
    pub(crate) next_sibling: u32,
    pub(crate) data: NodeData,
}

pub(crate) enum NodeData {
    Document,
    Doctype(String),
    Element(Element),
    Text(String),
    Comment(String),
    /// Markup browsers drop (end-tag attributes, a tag cut off at the end of the input); kept
    /// for `security_text` only.
    Unparsed(String),
}

pub(crate) struct Element {
    /// Lower-case tag name.
    pub(crate) name: Box<str>,
    /// Attributes in source order (the tokenizer keeps the first of duplicates).
    pub(crate) attrs: Vec<(Box<str>, Box<str>)>,
}

impl Element {
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| &**n == name)
            .map(|(_, v)| &**v)
    }

    pub(crate) fn has_attr(&self, name: &str) -> bool {
        self.attrs.iter().any(|(n, _)| &**n == name)
    }

    pub(crate) fn is(&self, name: &str) -> bool {
        &*self.name == name
    }
}

/// Too many nodes.
#[derive(Debug)]
pub(crate) struct TooManyNodes;

pub(crate) struct Dom {
    pub(crate) nodes: Vec<Node>,
}

impl Dom {
    pub(crate) fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }

    pub(crate) fn element(&self, id: NodeId) -> Option<&Element> {
        match &self.node(id).data {
            NodeData::Element(element) => Some(element),
            _ => None,
        }
    }

    pub(crate) fn first_child(&self, id: NodeId) -> Option<NodeId> {
        link(self.node(id).first_child)
    }

    pub(crate) fn next_sibling(&self, id: NodeId) -> Option<NodeId> {
        link(self.node(id).next_sibling)
    }

    pub(crate) fn parent(&self, id: NodeId) -> Option<NodeId> {
        link(self.node(id).parent)
    }

    /// Depth-first walk of the subtree at `root` (iterative). `visit` sees `Enter(id)` and, for
    /// every entered node whose children were not skipped, `Exit(id)` after them. Returning
    /// `Walk::Skip` from an `Enter` skips the node's children (and still produces its `Exit`).
    pub(crate) fn walk<E>(
        &self,
        root: NodeId,
        mut visit: impl FnMut(Event) -> Result<Walk, E>,
    ) -> Result<(), E> {
        let mut id = root;
        loop {
            #[cfg(test)]
            crate::work::walk_step();
            let descend = visit(Event::Enter(id))? == Walk::Continue;
            if descend {
                if let Some(child) = self.first_child(id) {
                    id = child;
                    continue;
                }
            }
            loop {
                #[cfg(test)]
                crate::work::walk_step();
                visit(Event::Exit(id))?;
                if id == root {
                    return Ok(());
                }
                if let Some(sibling) = self.next_sibling(id) {
                    id = sibling;
                    break;
                }
                match self.parent(id) {
                    Some(parent) => id = parent,
                    None => return Ok(()),
                }
            }
        }
    }

    /// Every node id in document order (the arena is appended in document order).
    #[cfg(test)]
    pub(crate) fn ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        (0..self.nodes.len()).filter_map(|i| u32::try_from(i).ok())
    }
}

/// A walk event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Enter(NodeId),
    Exit(NodeId),
}

/// Walk control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Walk {
    Continue,
    Skip,
}

fn link(value: u32) -> Option<NodeId> {
    (value != NONE).then_some(value)
}

/// Elements with no content and no end tag.
fn is_void(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "basefont"
            | "bgsound"
            | "br"
            | "col"
            | "embed"
            | "frame"
            | "hr"
            | "img"
            | "input"
            | "keygen"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

/// Start tags that close an open `<p>` at the top of the stack.
fn closes_p(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "center"
            | "details"
            | "dialog"
            | "dir"
            | "div"
            | "dl"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hgroup"
            | "hr"
            | "main"
            | "menu"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "summary"
            | "table"
            | "ul"
    )
}

fn is_heading(name: &str) -> bool {
    matches!(name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}

struct Builder {
    dom: Dom,
    /// Open elements (ids); `stack[0]` is the root and is never popped.
    stack: Vec<NodeId>,
    /// Open `svg`/`math` elements: self-closing start tags are honoured inside them.
    foreign_depth: usize,
}

impl Builder {
    fn new() -> Self {
        Self {
            dom: Dom {
                nodes: vec![Node {
                    parent: NONE,
                    first_child: NONE,
                    last_child: NONE,
                    next_sibling: NONE,
                    data: NodeData::Document,
                }],
            },
            stack: vec![ROOT],
            foreign_depth: 0,
        }
    }

    fn current(&self) -> NodeId {
        self.stack.last().copied().unwrap_or(ROOT)
    }

    fn append(&mut self, data: NodeData) -> Result<NodeId, TooManyNodes> {
        if self.dom.nodes.len() >= MAX_NODES {
            return Err(TooManyNodes);
        }
        let id = u32::try_from(self.dom.nodes.len()).map_err(|_| TooManyNodes)?;
        let parent = self.current();
        let previous = self.dom.nodes[parent as usize].last_child;
        self.dom.nodes.push(Node {
            parent,
            first_child: NONE,
            last_child: NONE,
            next_sibling: NONE,
            data,
        });
        if previous == NONE {
            self.dom.nodes[parent as usize].first_child = id;
        } else {
            self.dom.nodes[previous as usize].next_sibling = id;
        }
        self.dom.nodes[parent as usize].last_child = id;
        Ok(id)
    }

    fn text(&mut self, text: &str) -> Result<(), TooManyNodes> {
        if text.is_empty() {
            return Ok(());
        }
        let parent = self.current();
        let last = self.dom.nodes[parent as usize].last_child;
        if last != NONE {
            if let NodeData::Text(existing) = &mut self.dom.nodes[last as usize].data {
                existing.push_str(text);
                return Ok(());
            }
        }
        self.append(NodeData::Text(text.to_owned())).map(|_| ())
    }

    fn open_name(&self, id: NodeId) -> Option<&str> {
        self.dom.element(id).map(|e| &*e.name)
    }

    fn pop(&mut self) {
        if self.stack.len() > 1 {
            if let Some(id) = self.stack.pop() {
                if matches!(self.open_name(id), Some("svg" | "math")) {
                    self.foreign_depth = self.foreign_depth.saturating_sub(1);
                }
            }
        }
    }

    /// Pop through the nearest open element for which `matches` holds, searching at most
    /// `limit` elements and stopping at a `boundary` element. Returns whether one was found.
    fn close_through(
        &mut self,
        limit: usize,
        matches: impl Fn(&str) -> bool,
        boundary: impl Fn(&str) -> bool,
    ) -> bool {
        let found = self
            .stack
            .iter()
            .enumerate()
            .skip(1)
            .rev()
            .take(limit)
            .find_map(|(index, &id)| {
                #[cfg(test)]
                crate::work::stack_scan_step();
                let name = self.open_name(id)?;
                if matches(name) {
                    Some(Some(index))
                } else if boundary(name) {
                    Some(None)
                } else {
                    None
                }
            })
            .flatten();
        match found {
            Some(index) => {
                while self.stack.len() > index {
                    self.pop();
                }
                true
            }
            None => false,
        }
    }

    fn implied_end_tags(&mut self, name: &str) {
        if closes_p(name) && self.open_name(self.current()) == Some("p") {
            self.pop();
        }
        match name {
            "li" => {
                self.close_through(
                    MAX_IMPLIED_SCAN,
                    |n| n == "li",
                    |n| matches!(n, "ul" | "ol" | "menu"),
                );
            }
            "dt" | "dd" => {
                self.close_through(MAX_IMPLIED_SCAN, |n| n == "dt" || n == "dd", |n| n == "dl");
            }
            "tr" => {
                self.close_through(MAX_IMPLIED_SCAN, |n| n == "tr", |n| n == "table");
            }
            "td" | "th" => {
                self.close_through(
                    MAX_IMPLIED_SCAN,
                    |n| n == "td" || n == "th",
                    |n| n == "tr" || n == "table",
                );
            }
            "thead" | "tbody" | "tfoot" => {
                self.close_through(
                    MAX_IMPLIED_SCAN,
                    |n| matches!(n, "thead" | "tbody" | "tfoot"),
                    |n| n == "table",
                );
            }
            "option" => {
                if self.open_name(self.current()) == Some("option") {
                    self.pop();
                }
            }
            "a" => {
                self.close_through(MAX_IMPLIED_SCAN, |n| n == "a", |_| false);
            }
            _ if is_heading(name) && self.open_name(self.current()).is_some_and(is_heading) => {
                self.pop();
            }
            _ => {}
        }
    }

    fn start_tag(
        &mut self,
        name: String,
        attrs: Vec<(Box<str>, Box<str>)>,
        self_closing: bool,
    ) -> Result<(), TooManyNodes> {
        if self.foreign_depth == 0 {
            self.implied_end_tags(&name);
        }
        let foreign = matches!(name.as_str(), "svg" | "math");
        let void = is_void(&name) || (self_closing && (self.foreign_depth > 0 || foreign));
        let id = self.append(NodeData::Element(Element {
            name: name.into_boxed_str(),
            attrs,
        }))?;
        if !void {
            self.stack.push(id);
            if foreign {
                self.foreign_depth += 1;
            }
        }
        Ok(())
    }

    fn end_tag(&mut self, name: &str) -> Result<(), TooManyNodes> {
        match name {
            // Content after `</body>` / `</html>` still belongs to the body.
            "body" | "html" => Ok(()),
            // `</br>` is treated as `<br>`.
            "br" => self.start_tag("br".to_owned(), Vec::new(), false),
            _ => {
                self.close_through(MAX_END_TAG_SCAN, |n| n == name, |_| false);
                Ok(())
            }
        }
    }
}

/// Parse `source` into a [`Dom`].
pub(crate) fn parse(source: &str) -> Result<Dom, TooManyNodes> {
    let mut builder = Builder::new();
    tokenize(source, |token| match token {
        Token::StartTag {
            name,
            attrs,
            self_closing,
        } => {
            let attrs = attrs
                .into_iter()
                .map(|(key, value)| (key.into_boxed_str(), value.into_boxed_str()))
                .collect();
            builder.start_tag(name, attrs, self_closing)
        }
        Token::EndTag { name, attrs } => {
            if !attrs.is_empty() {
                builder.append(NodeData::Unparsed(attrs.join("\n")))?;
            }
            builder.end_tag(&name)
        }
        Token::Text(text) => builder.text(&text),
        Token::Comment(text) => builder
            .append(NodeData::Comment(text.to_owned()))
            .map(|_| ()),
        Token::Doctype(text) => builder
            .append(NodeData::Doctype(text.to_owned()))
            .map(|_| ()),
        Token::Unparsed(text) => builder
            .append(NodeData::Unparsed(text.to_owned()))
            .map(|_| ()),
    })?;
    Ok(builder.dom)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(dom: &Dom, parent: NodeId) -> Vec<String> {
        let mut out = Vec::new();
        let mut child = dom.first_child(parent);
        while let Some(id) = child {
            out.push(match &dom.node(id).data {
                NodeData::Element(e) => e.name.to_string(),
                NodeData::Text(t) => format!("#{t}"),
                NodeData::Comment(_) | NodeData::Unparsed(_) => "!".into(),
                NodeData::Doctype(_) => "doctype".into(),
                NodeData::Document => "document".into(),
            });
            child = dom.next_sibling(id);
        }
        out
    }

    fn find(dom: &Dom, name: &str) -> NodeId {
        dom.ids()
            .find(|&id| dom.element(id).is_some_and(|e| e.is(name)))
            .unwrap()
    }

    #[test]
    fn builds_nested_elements_with_implied_ends() {
        let dom = parse("<ul><li>a<li>b</ul><p>x<div>y</div>").unwrap();
        let ul = find(&dom, "ul");
        assert_eq!(names(&dom, ul), ["li", "li"]);
        assert_eq!(names(&dom, ROOT), ["ul", "p", "div"]);
    }

    #[test]
    fn raw_text_elements_hold_markup_as_text() {
        let dom =
            parse("<script>if (a<b) { x = '</p>'; }</script><title>a <b> &amp; c</title>").unwrap();
        let script = find(&dom, "script");
        assert_eq!(names(&dom, script), ["#if (a<b) { x = '</p>'; }"]);
        let title = find(&dom, "title");
        assert_eq!(names(&dom, title), ["#a <b> & c"]);
    }

    #[test]
    fn entities_are_decoded_once() {
        let dom = parse("<p title=\"&amp;lt;\">&amp;lt;&#x41;</p>").unwrap();
        let p = find(&dom, "p");
        assert_eq!(names(&dom, p), ["#&lt;A"]);
        assert_eq!(dom.element(p).unwrap().attr("title"), Some("&lt;"));
    }

    #[test]
    fn stray_end_tags_are_ignored_and_body_end_keeps_body_open() {
        let dom = parse("<body><p>a</span></p></body>tail").unwrap();
        let body = find(&dom, "body");
        assert_eq!(names(&dom, body), ["p", "#tail"]);
    }

    #[test]
    fn self_closing_is_honoured_only_in_foreign_content() {
        let dom = parse("<div/>in<svg><path/><g/>t</svg>").unwrap();
        let div = find(&dom, "div");
        assert_eq!(names(&dom, div), ["#in", "svg"]);
        let svg = find(&dom, "svg");
        assert_eq!(names(&dom, svg), ["path", "g", "#t"]);
    }

    #[test]
    fn walk_visits_in_document_order_without_recursion() {
        let depth = 200_000;
        let source = "<div>".repeat(depth) + "x";
        let dom = parse(&source).unwrap();
        let mut entered = 0usize;
        let mut exited = 0usize;
        dom.walk::<()>(ROOT, |event| {
            match event {
                Event::Enter(_) => entered += 1,
                Event::Exit(_) => exited += 1,
            }
            Ok(Walk::Continue)
        })
        .unwrap();
        assert_eq!(entered, depth + 2);
        assert_eq!(exited, depth + 2);
    }

    #[test]
    fn node_count_is_capped() {
        let source = "<i>".repeat(MAX_NODES + 1);
        assert!(parse(&source).is_err());
    }
}
