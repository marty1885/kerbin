//! HTML is parsed as a browser-style DOM; no JavaScript is executed.
use dom_smoothie::{Config, Readability};
use scraper::{ElementRef, Html, Selector};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use url::Url;

#[derive(Debug, PartialEq)]
pub enum RenderError {
    TooComplex,
    TooLarge,
}
const MAX_NODES: usize = 50_000;
const MAX_DEPTH: usize = 128;
fn validate_document(doc: &Html) -> Result<(), RenderError> {
    let root = doc.tree.root();
    if root.descendants().take(MAX_NODES + 1).count() > MAX_NODES {
        return Err(RenderError::TooComplex);
    }
    if root
        .descendants()
        .any(|node| node.ancestors().take(MAX_DEPTH + 1).count() > MAX_DEPTH)
    {
        return Err(RenderError::TooComplex);
    }
    Ok(())
}
pub fn html_to_gemtext(
    html: &str,
    url: &Url,
    full_page: bool,
    max_output: usize,
) -> Result<String, RenderError> {
    if !full_page {
        // Keep directory/index pages intact; delegate article detection and
        // cleanup to Readability rather than maintaining our own heuristics.
        let doc = Html::parse_document(html);
        validate_document(&doc)?;
        let base = document_base(&doc, url);
        if let Ok(mut reader) = Readability::new(
            html,
            Some(base.as_str()),
            Some(Config {
                max_elements_to_parse: MAX_NODES,
                ..Config::default()
            }),
        ) && reader.is_probably_readable()
            && let Ok(article) = reader.parse()
            && !article.text_content.trim().is_empty()
        {
            let body = render_document(&article.content, &base, max_output)?;
            if !body.trim().is_empty() {
                let title = clean(&article.title);
                let result = if title.is_empty() {
                    body
                } else {
                    format!("# {title}\n\n{body}")
                };
                return if result.len() <= max_output {
                    Ok(result)
                } else {
                    Err(RenderError::TooLarge)
                };
            }
        }
    }
    render_document(html, url, max_output)
}

fn document_base(doc: &Html, url: &Url) -> Url {
    doc.select(&Selector::parse("base[href]").unwrap())
        .next()
        .and_then(|e| url.join(e.value().attr("href")?).ok())
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .unwrap_or_else(|| url.clone())
}

fn render_document(html: &str, url: &Url, max_output: usize) -> Result<String, RenderError> {
    let doc = Html::parse_document(html);
    validate_document(&doc)?;
    let select = |s| Selector::parse(s).unwrap();
    let base = document_base(&doc, url);
    let mut r = Renderer {
        base,
        output: String::new(),
        text: String::new(),
        prefix: String::new(),
        links: vec![],
        link_indices: HashMap::new(),
        link_bytes: 0,
        pending: vec![],
        pending_indices: HashSet::new(),
        limit: max_output,
        failed: false,
    };
    if let Some(title) = doc.select(&select("title")).next() {
        let title = clean(&title.text().collect::<String>());
        if !title.is_empty() {
            r.emit(&format!("# {title}\n\n"));
        }
    }
    if let Some(body) = doc.select(&select("body")).next() {
        r.walk(body);
    }
    r.flush();
    if r.failed {
        Err(RenderError::TooLarge)
    } else {
        Ok(r.output)
    }
}

fn clean(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

struct Renderer {
    base: Url,
    output: String,
    text: String,
    prefix: String,
    links: Vec<Arc<(Url, String)>>,
    link_indices: HashMap<Arc<(Url, String)>, usize>,
    link_bytes: usize,
    pending: Vec<usize>,
    pending_indices: HashSet<usize>,
    limit: usize,
    failed: bool,
}
impl Renderer {
    fn emit(&mut self, value: &str) {
        if value.len() > self.limit.saturating_sub(self.output.len()) {
            self.failed = true;
        } else if !self.failed {
            self.output.push_str(value);
        }
    }
    fn emit_char(&mut self, value: char) {
        let mut buffer = [0; 4];
        self.emit(value.encode_utf8(&mut buffer));
    }
    fn write_text(&mut self, value: &str) {
        if value.len() > self.limit.saturating_sub(self.text.len()) {
            self.failed = true;
        } else if !self.failed {
            self.text.push_str(value);
        }
    }
    fn flush(&mut self) {
        let text = clean(&std::mem::take(&mut self.text));
        let has_content = !text.is_empty() || !self.pending.is_empty();
        if !text.is_empty() {
            let escape = self.prefix.is_empty()
                && ["#", "=>", "* ", ">", "```"]
                    .iter()
                    .any(|p| text.starts_with(p));
            let prefix = self.prefix.clone();
            self.emit(&prefix);
            if escape {
                self.emit_char('\\');
            }
            self.emit(&text);
            self.emit("\n");
        }
        // Place real Gemtext links immediately after the text that references
        // them. Image links need no synthetic paragraph containing only [n].
        let pending = std::mem::take(&mut self.pending);
        self.pending_indices.clear();
        for index in pending {
            let entry = self.links[index].clone();
            self.emit(&format!("=> {} [{}] {}\n", entry.0, index + 1, entry.1));
            if self.failed {
                break;
            }
        }
        if has_content {
            self.emit("\n");
        }
    }
    fn link(&mut self, target: &str, label: &str, inline_reference: bool) {
        let Ok(url) = self.base.join(target) else {
            return;
        };
        if !matches!(
            url.scheme(),
            "http" | "https" | "gemini" | "gopher" | "mailto"
        ) {
            return;
        }
        let label = clean(label);
        let label = if label.is_empty() {
            url.to_string()
        } else {
            label
        };
        // Gemini request URLs are limited to 1024 bytes. Limit buffered link
        // material and use hashed deduplication instead of quadratic scans.
        if url.as_str().len() > 1024 {
            return;
        }
        let entry = Arc::new((url, label));
        let index = if let Some(index) = self.link_indices.get(&entry) {
            *index
        } else {
            let bytes = entry.0.as_str().len() + entry.1.len() + 32;
            if self.links.len() >= 4096 || bytes > self.limit.saturating_sub(self.link_bytes) {
                self.failed = true;
                return;
            }
            self.link_bytes += bytes;
            let index = self.links.len();
            self.links.push(entry.clone());
            self.link_indices.insert(entry, index);
            index
        };
        if self.pending_indices.insert(index) {
            self.pending.push(index);
        }
        if inline_reference {
            self.write_text(&format!(" [{}]", index + 1));
        }
    }
    fn walk(&mut self, el: ElementRef<'_>) {
        if self.failed {
            return;
        }
        let tag = el.value().name();
        if matches!(tag, "head" | "script" | "style" | "template" | "noscript")
            || el.value().attr("hidden").is_some()
            || el.value().attr("aria-hidden") == Some("true")
        {
            return;
        }
        if tag == "a"
            && el.text().all(|text| text.trim().is_empty())
            && let Some(image) = el
                .descendants()
                .filter_map(ElementRef::wrap)
                .find(|child| child.value().name() == "img")
            && let Some(href) = el.value().attr("href")
        {
            let alt = clean(image.value().attr("alt").unwrap_or(""));
            self.link(href, if alt.is_empty() { "Image" } else { &alt }, false);
            return;
        }
        if tag == "pre" {
            self.flush();
            self.emit("```\n");
            let content = el
                .text()
                .collect::<String>()
                .replace("\r\n", "\n")
                .replace('\r', "\n");
            for line in content.lines() {
                if self.failed {
                    break;
                }
                if line.starts_with("```") {
                    self.emit_char(' ');
                }
                self.emit(line);
                self.emit_char('\n');
            }
            self.emit("```\n\n");
            return;
        }
        if tag == "br" {
            self.flush();
            return;
        }
        if tag == "hr" {
            self.flush();
            self.emit("─────\n\n");
            return;
        }
        let block = matches!(
            tag,
            "p" | "div"
                | "section"
                | "article"
                | "main"
                | "header"
                | "footer"
                | "nav"
                | "aside"
                | "ul"
                | "ol"
                | "li"
                | "blockquote"
                | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "h5"
                | "h6"
                | "tr"
                | "dl"
                | "dt"
                | "dd"
                | "figure"
                | "figcaption"
        );
        if block {
            self.flush();
        }
        let previous = self.prefix.clone();
        match tag {
            "h1" => self.prefix = "# ".into(),
            "h2" => self.prefix = "## ".into(),
            "h3" | "h4" | "h5" | "h6" => self.prefix = "### ".into(),
            "li" => self.prefix = "* ".into(),
            "blockquote" => self.prefix = "> ".into(),
            _ => {}
        }
        if tag == "img" {
            let alt = clean(el.value().attr("alt").unwrap_or(""));
            if let Some(src) = el.value().attr("src").filter(|src| !src.trim().is_empty()) {
                self.link(src, if alt.is_empty() { "Image" } else { &alt }, false);
            } else if !alt.is_empty() {
                self.write_text(&alt);
            }
        } else {
            for child in el.children() {
                if let Some(text) = child.value().as_text() {
                    self.write_text(text);
                } else if let Some(child) = ElementRef::wrap(child) {
                    self.walk(child);
                }
            }
        }
        if tag == "a"
            && let Some(href) = el.value().attr("href")
        {
            self.link(href, &el.text().collect::<String>(), true);
        }
        if matches!(tag, "td" | "th") {
            self.write_text(" | ");
        }
        if block {
            self.flush();
        }
        self.prefix = previous;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn render(html: &str) -> String {
        html_to_gemtext(
            html,
            &Url::parse("https://example.org/path/page").unwrap(),
            false,
            1024 * 1024,
        )
        .unwrap()
    }
    #[test]
    fn preserves_structure_and_resolves_links() {
        let result = render(
            "<title>A &amp; B</title><h1>Heading</h1><p>Hello <b>world</b>, <a href='../next?q=1&amp;x=2'>go</a>!</p><ul><li>One</li><li>Two</li></ul><blockquote><p>Quote</p></blockquote>",
        );
        assert!(result.contains("# A & B\n"));
        assert!(result.contains("Hello world, go [1]!"));
        assert!(result.contains("* One\n"));
        assert!(result.contains("> Quote\n"));
        assert!(result.contains("=> https://example.org/next?q=1&x=2 [1] go"));
    }
    #[test]
    fn ignores_non_content_and_unsafe_links() {
        let result = render(
            "<script>bad</script><style>bad</style><p hidden>bad</p><p>Good <a href='javascript:alert(1)'>link</a></p>",
        );
        assert!(!result.contains("bad"));
        assert!(!result.contains("javascript:"));
        assert!(result.contains("Good link"));
    }
    #[test]
    fn base_images_pre_and_literal_directives() {
        let result = render(
            "<base href='https://cdn.example.org/'><p>=> literal</p><img src='a.png' alt='Picture'><pre>a\n  b\n```oops</pre><a href='x'>X</a>",
        );
        assert!(result.contains("\\=> literal"));
        assert!(result.contains("=> https://cdn.example.org/a.png"));
        assert!(result.contains("```\na\n  b\n ```oops\n```"));
        assert!(result.contains("=> https://cdn.example.org/x"));
    }
    #[test]
    fn readability_removes_boilerplate_and_full_page_can_restore_it() {
        let paragraph = "An expedition explores the mountains and studies the changing landscape. Along the way, researchers collect detailed observations, discuss their findings, and document the history of the region. This account describes what they learned and why those results matter to future exploration.";
        let html = format!(
            "<html><head><title>Mountain expedition report</title><base href='https://cdn.example.org/articles/'></head><body><nav><a href='/subscribe'>Subscribe now</a></nav><article><h1>Mountain expedition report</h1>{}<p>Read the <a href='notes'>field notes</a>.</p></article><footer>Unrelated footer material</footer></body></html>",
            format!("<p>{paragraph}</p>").repeat(6)
        );
        let url = Url::parse("https://example.org/page").unwrap();
        let article = html_to_gemtext(&html, &url, false, 1024 * 1024).unwrap();
        assert!(article.contains("An expedition explores"));
        assert!(!article.contains("Subscribe now"), "{article}");
        assert!(!article.contains("Unrelated footer material"), "{article}");
        assert!(
            article.contains("=> https://cdn.example.org/articles/notes"),
            "{article}"
        );
        let full = html_to_gemtext(&html, &url, true, 1024 * 1024).unwrap();
        assert!(full.contains("Subscribe now"));
        assert!(full.contains("Unrelated footer material"));
    }
    #[test]
    fn index_pages_fall_back_to_full_document() {
        let result =
            render("<h1>Directory</h1><nav><a href='/a'>Page A</a><a href='/b'>Page B</a></nav>");
        assert!(result.contains("Page A"));
        assert!(result.contains("Page B"));
        assert!(result.contains("=> https://example.org/a"));
    }
    #[test]
    fn depth_node_and_output_limits_are_enforced() {
        let url = Url::parse("https://example.org/").unwrap();
        let deep = format!("{}text{}", "<div>".repeat(140), "</div>".repeat(140));
        assert_eq!(
            html_to_gemtext(&deep, &url, true, 1024).unwrap_err(),
            RenderError::TooComplex
        );
        let many = "<br>".repeat(50_001);
        assert_eq!(
            html_to_gemtext(&many, &url, true, 1024).unwrap_err(),
            RenderError::TooComplex
        );
        assert_eq!(
            html_to_gemtext("<p>too much text here</p>", &url, false, 8).unwrap_err(),
            RenderError::TooLarge
        );
        let links = (0..5000)
            .map(|n| format!("<a href='/link/{n}'>x</a>"))
            .collect::<String>();
        assert_eq!(
            html_to_gemtext(&links, &url, true, 1024 * 1024).unwrap_err(),
            RenderError::TooLarge
        );
    }
    #[test]
    fn links_follow_their_paragraph_and_images_have_no_orphan_reference_lines() {
        let result = render(
            "<p>First <a href='/one'>reference</a>.</p><p>Second <a href='/two'>reference</a>.</p>",
        );
        assert!(result.contains("First reference [1].\n=> https://example.org/one [1] reference\n\nSecond reference [2].\n=> https://example.org/two [2] reference"), "{result}");
        assert!(!result.contains("## Links"));
        let result = render(
            "<p>Here is a poster and its homage.</p><figure><img src='/poster.jpg' alt='Movie poster'></figure><figure><a href='/homage.jpg'><img src='/thumb.jpg' alt='Buscema homage'></a></figure><p>Here is a <a href='/discussion'>commenter</a> defining swipes.</p>",
        );
        assert!(
            result.contains("=> https://example.org/poster.jpg [1] Movie poster"),
            "{result}"
        );
        assert!(
            result.contains("=> https://example.org/homage.jpg [2] Buscema homage"),
            "{result}"
        );
        assert!(!result.contains("thumb.jpg"));
        assert!(
            !result
                .lines()
                .any(|line| matches!(line.trim(), "[1]" | "[2]"))
        );
        let image_position = result.find("=> https://example.org/homage.jpg").unwrap();
        let next_paragraph = result.find("Here is a commenter").unwrap();
        assert!(image_position < next_paragraph);
        assert!(result.contains("Here is a commenter [3] defining swipes.\n=> https://example.org/discussion [3] commenter"), "{result}");
    }
    #[test]
    fn repeated_links_are_emitted_locally_in_each_paragraph() {
        let result = render(
            "<p><a href='/one'>One</a> and <a href='/one'>One</a>.</p><p>Again <a href='/one'>One</a>.</p>",
        );
        assert_eq!(
            result.matches("=> https://example.org/one [1] One").count(),
            2
        );
        assert!(result.contains("Again One [1].\n=> https://example.org/one [1] One"));
    }
}
