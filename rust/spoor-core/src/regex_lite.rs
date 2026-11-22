//! Minimal regex engine for policy patterns.
//!
//! The Python oracle evaluates policy with `re.search(pat, cmd, re.I)`. To keep
//! Rust semantically identical we parse the same pattern strings here instead of
//! approximating them with substring checks. Supported subset (all the policy
//! uses): literals, `.`, classes `[...]`/`[^...]` with ranges and `\s\d\w`,
//! groups `(...)`/`(?:...)`, alternation, quantifiers `* + ? {m,n}`, anchors
//! `^ $`, `\b`, negative/positive lookahead `(?!...)`/`(?=...)`.
//!
//! Matching is a small backtracking engine returning all reachable end
//! positions, with a step budget so pathological patterns cannot hang the
//! broker.

#[derive(Debug, Clone)]
enum ClassItem {
    Char(char),
    Range(char, char),
    Space,
    NotSpace,
    Digit,
    NotDigit,
    Word,
    NotWord,
}

#[derive(Debug, Clone)]
struct Class {
    neg: bool,
    items: Vec<ClassItem>,
}

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Any,
    Class(Class),
    Start,
    End,
    Boundary,
    Group(Vec<Node>),
    Alt(Vec<Vec<Node>>),
    Repeat(Box<Node>, usize, Option<usize>),
    Look { negative: bool, node: Vec<Node> },
}

pub struct Regex {
    nodes: Vec<Node>,
    case_insensitive: bool,
    #[cfg(test)]
    pub(crate) step_budget: usize,
}

const BUDGET: usize = 500_000;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MatchBudgetExhausted;

impl Regex {
    pub fn new(pattern: &str, case_insensitive: bool) -> Result<Self, String> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut parser = Parser { chars, index: 0 };
        let nodes = parser.parse()?;
        Ok(Regex {
            nodes,
            case_insensitive,
            #[cfg(test)]
            step_budget: BUDGET,
        })
    }

    /// Conservative match for callers that only derive advisory labels.
    pub fn is_match(&self, text: &str) -> bool {
        self.try_is_match(text).unwrap_or(true)
    }

    pub(crate) fn try_is_match(&self, text: &str) -> Result<bool, MatchBudgetExhausted> {
        let chars: Vec<char> = text.chars().collect();
        #[cfg(not(test))]
        let mut budget = BUDGET;
        #[cfg(test)]
        let mut budget = self.step_budget;
        for start in 0..=chars.len() {
            if !self
                .match_seq(&self.nodes, &chars, start, &mut budget)?
                .is_empty()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn match_seq(
        &self,
        nodes: &[Node],
        text: &[char],
        pos: usize,
        budget: &mut usize,
    ) -> Result<Vec<usize>, MatchBudgetExhausted> {
        if nodes.is_empty() {
            return Ok(vec![pos]);
        }
        spend_step(budget)?;
        let ends = self.match_node(&nodes[0], text, pos, budget)?;
        let mut out = Vec::new();
        for end in ends {
            for result in self.match_seq(&nodes[1..], text, end, budget)? {
                if !out.contains(&result) {
                    out.push(result);
                }
            }
        }
        Ok(out)
    }

    fn match_node(
        &self,
        node: &Node,
        text: &[char],
        pos: usize,
        budget: &mut usize,
    ) -> Result<Vec<usize>, MatchBudgetExhausted> {
        spend_step(budget)?;
        Ok(match node {
            Node::Char(expected) => {
                if pos < text.len() && self.eq_char(*expected, text[pos]) {
                    vec![pos + 1]
                } else {
                    Vec::new()
                }
            }
            Node::Any => {
                if pos < text.len() && text[pos] != '\n' {
                    vec![pos + 1]
                } else {
                    Vec::new()
                }
            }
            Node::Class(class) => {
                if pos < text.len() && self.class_matches(class, text[pos]) {
                    vec![pos + 1]
                } else {
                    Vec::new()
                }
            }
            Node::Start => {
                if pos == 0 {
                    vec![pos]
                } else {
                    Vec::new()
                }
            }
            Node::End => {
                if pos == text.len() {
                    vec![pos]
                } else {
                    Vec::new()
                }
            }
            Node::Boundary => {
                let before = pos > 0 && is_word(text[pos - 1]);
                let after = pos < text.len() && is_word(text[pos]);
                if before != after {
                    vec![pos]
                } else {
                    Vec::new()
                }
            }
            Node::Group(inner) => return self.match_seq(inner, text, pos, budget),
            Node::Alt(options) => {
                let mut out = Vec::new();
                for option in options {
                    for end in self.match_seq(option, text, pos, budget)? {
                        if !out.contains(&end) {
                            out.push(end);
                        }
                    }
                }
                out
            }
            Node::Look { negative, node } => {
                let inner = self.match_seq(node, text, pos, budget)?;
                let matched = !inner.is_empty();
                if matched != *negative {
                    vec![pos]
                } else {
                    Vec::new()
                }
            }
            Node::Repeat(inner, min, max) => {
                let mut result = Vec::new();
                if *min == 0 {
                    result.push(pos);
                }
                let mut frontier = vec![pos];
                let mut count = 0usize;
                let limit = max.unwrap_or(text.len() + 1);
                while count < limit {
                    let mut next = Vec::new();
                    for from in &frontier {
                        for end in self.match_node(inner, text, *from, budget)? {
                            if !next.contains(&end) {
                                next.push(end);
                            }
                        }
                    }
                    if next.is_empty() {
                        break;
                    }
                    count += 1;
                    if count >= *min {
                        for end in &next {
                            if !result.contains(end) {
                                result.push(*end);
                            }
                        }
                    }
                    frontier = next;
                    if count > text.len() + 1 {
                        break;
                    }
                }
                result
            }
        })
    }

    fn class_matches(&self, class: &Class, ch: char) -> bool {
        let mut hit = false;
        for item in &class.items {
            let matched = match item {
                ClassItem::Char(expected) => self.eq_char(*expected, ch),
                ClassItem::Range(start, end) => {
                    let lower = ch.to_ascii_lowercase();
                    lower >= *start && lower <= *end
                }
                ClassItem::Space => ch.is_whitespace(),
                ClassItem::NotSpace => !ch.is_whitespace(),
                ClassItem::Digit => ch.is_ascii_digit(),
                ClassItem::NotDigit => !ch.is_ascii_digit(),
                ClassItem::Word => is_word(ch),
                ClassItem::NotWord => !is_word(ch),
            };
            if matched {
                hit = true;
                break;
            }
        }
        hit != class.neg
    }

    fn eq_char(&self, expected: char, actual: char) -> bool {
        if self.case_insensitive {
            expected.to_ascii_lowercase() == actual.to_ascii_lowercase()
        } else {
            expected == actual
        }
    }
}

fn is_word(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

struct Parser {
    chars: Vec<char>,
    index: usize,
}

impl Parser {
    fn parse(&mut self) -> Result<Vec<Node>, String> {
        let nodes = self.alternation()?;
        if self.index != self.chars.len() {
            return Err(format!(
                "unexpected '{}' at {}",
                self.chars[self.index], self.index
            ));
        }
        Ok(nodes)
    }

    fn alternation(&mut self) -> Result<Vec<Node>, String> {
        let mut options = vec![self.sequence()?];
        while self.peek() == Some('|') {
            self.index += 1;
            options.push(self.sequence()?);
        }
        Ok(if options.len() == 1 {
            options.pop().unwrap()
        } else {
            vec![Node::Alt(options)]
        })
    }

    fn sequence(&mut self) -> Result<Vec<Node>, String> {
        let mut nodes = Vec::new();
        while let Some(ch) = self.peek() {
            if ch == ')' || ch == '|' {
                break;
            }
            nodes.push(self.atom()?);
        }
        Ok(nodes)
    }

    fn atom(&mut self) -> Result<Node, String> {
        let mut node = match self.next() {
            Some('(') => self.group()?,
            Some('[') => Node::Class(self.class()?),
            Some('\\') => self.escape()?,
            Some('^') => Node::Start,
            Some('$') => Node::End,
            Some('.') => Node::Any,
            Some(ch) => Node::Char(ch),
            None => return Err("unexpected end of pattern".into()),
        };
        if let Some(ch) = self.peek() {
            let quantifier = match ch {
                '*' => Some((0, None)),
                '+' => Some((1, None)),
                '?' => Some((0, Some(1))),
                '{' => self.brace_quantifier()?,
                _ => None,
            };
            if let Some((min, max)) = quantifier {
                if ch != '{' {
                    self.index += 1;
                }
                node = Node::Repeat(Box::new(node), min, max);
            }
        }
        Ok(node)
    }

    fn brace_quantifier(&mut self) -> Result<Option<(usize, Option<usize>)>, String> {
        let start = self.index;
        if self.peek() != Some('{') {
            return Ok(None);
        }
        self.index += 1;
        let mut digits = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                digits.push(ch);
                self.index += 1;
            } else {
                break;
            }
        }
        if digits.is_empty() {
            self.index = start;
            return Ok(None);
        }
        let min: usize = digits.parse().map_err(|_| "bad quantifier".to_string())?;
        let max = match self.peek() {
            Some('}') => {
                self.index += 1;
                Some(min)
            }
            Some(',') => {
                self.index += 1;
                let mut other = String::new();
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_digit() {
                        other.push(ch);
                        self.index += 1;
                    } else {
                        break;
                    }
                }
                if self.peek() != Some('}') {
                    self.index = start;
                    return Ok(None);
                }
                self.index += 1;
                if other.is_empty() {
                    None
                } else {
                    Some(other.parse().map_err(|_| "bad quantifier".to_string())?)
                }
            }
            _ => {
                self.index = start;
                return Ok(None);
            }
        };
        Ok(Some((min, max)))
    }

    fn group(&mut self) -> Result<Node, String> {
        if self.peek() == Some('?') {
            self.index += 1;
            match self.next() {
                Some(':') => {
                    let inner = self.alternation()?;
                    self.expect(')')?;
                    Ok(Node::Group(inner))
                }
                Some('!') => {
                    let inner = self.alternation()?;
                    self.expect(')')?;
                    Ok(Node::Look {
                        negative: true,
                        node: inner,
                    })
                }
                Some('=') => {
                    let inner = self.alternation()?;
                    self.expect(')')?;
                    Ok(Node::Look {
                        negative: false,
                        node: inner,
                    })
                }
                other => Err(format!("unsupported group (?{:?}", other)),
            }
        } else {
            let inner = self.alternation()?;
            self.expect(')')?;
            Ok(Node::Group(inner))
        }
    }

    fn class(&mut self) -> Result<Class, String> {
        let neg = if self.peek() == Some('^') {
            self.index += 1;
            true
        } else {
            false
        };
        let mut items = Vec::new();
        loop {
            let ch = self
                .next()
                .ok_or_else(|| "unterminated class".to_string())?;
            if ch == ']' {
                break;
            }
            if ch == '\\' {
                items.push(self.class_escape()?);
                continue;
            }
            if self.peek() == Some('-') && self.peek_at(1) != Some(']') && self.peek_at(1).is_some()
            {
                self.index += 1;
                let end = self.next().unwrap();
                items.push(ClassItem::Range(ch, end));
                continue;
            }
            items.push(ClassItem::Char(ch));
        }
        Ok(Class { neg, items })
    }

    fn class_escape(&mut self) -> Result<ClassItem, String> {
        match self.next() {
            Some('s') => Ok(ClassItem::Space),
            Some('S') => Ok(ClassItem::NotSpace),
            Some('d') => Ok(ClassItem::Digit),
            Some('D') => Ok(ClassItem::NotDigit),
            Some('w') => Ok(ClassItem::Word),
            Some('W') => Ok(ClassItem::NotWord),
            Some(ch) => Ok(ClassItem::Char(ch)),
            None => Err("unterminated escape".into()),
        }
    }

    fn escape(&mut self) -> Result<Node, String> {
        match self.next() {
            Some('s') => Ok(Node::Class(Class {
                neg: false,
                items: vec![ClassItem::Space],
            })),
            Some('S') => Ok(Node::Class(Class {
                neg: false,
                items: vec![ClassItem::NotSpace],
            })),
            Some('d') => Ok(Node::Class(Class {
                neg: false,
                items: vec![ClassItem::Digit],
            })),
            Some('D') => Ok(Node::Class(Class {
                neg: false,
                items: vec![ClassItem::NotDigit],
            })),
            Some('w') => Ok(Node::Class(Class {
                neg: false,
                items: vec![ClassItem::Word],
            })),
            Some('W') => Ok(Node::Class(Class {
                neg: false,
                items: vec![ClassItem::NotWord],
            })),
            Some('b') => Ok(Node::Boundary),
            Some(ch) => Ok(Node::Char(ch)),
            None => Err("unterminated escape".into()),
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.index + offset).copied()
    }

    fn next(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.index += 1;
        Some(ch)
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        match self.next() {
            Some(ch) if ch == expected => Ok(()),
            other => Err(format!("expected '{}', got {:?}", expected, other)),
        }
    }
}

fn spend_step(budget: &mut usize) -> Result<(), MatchBudgetExhausted> {
    *budget = budget.checked_sub(1).ok_or(MatchBudgetExhausted)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, text: &str) -> bool {
        Regex::new(pattern, true)
            .unwrap()
            .try_is_match(text)
            .unwrap()
    }

    #[test]
    fn lookahead_propagates_incomplete_matches() {
        let mut pattern = Regex::new(r"^(?!b)a", true).unwrap();
        assert_eq!(pattern.try_is_match("a"), Ok(true));
        assert_eq!(pattern.try_is_match("b"), Ok(false));
        pattern.step_budget = 4;
        assert_eq!(pattern.try_is_match("a"), Err(MatchBudgetExhausted));
    }

    #[test]
    fn literals_classes_quantifiers() {
        assert!(m(r"rm\s+-rf\s+/", "rm  -rf /"));
        assert!(!m(r"rm\s+-rf\s+/", "rm -rf tmp"));
        assert!(m(r#"(^|[\s;"'])sqlmap(\s|$)"#, "bash -c sqlmap -u x"));
        assert!(m(r#"(^|[\s;"'])sqlmap(\s|$)"#, "SQLMAP -u x"));
        assert!(!m(r#"(^|[\s;"'])sqlmap(\s|$)"#, "notsqlmap -u x"));
        assert!(m(r"env\s*\|", "sh -c 'env|grep KEY'"));
        assert!(m(r"\.\.\.\s*\(\s*\)", "... ( )"));
    }

    #[test]
    fn lookahead_and_target_read() {
        let source = r"curl\s+(?!--data|--form|-d\b|-T\s|--upload-file|-X\s*POST)[^|&;]*(https?://(host\.docker\.internal|juice-shop|127\.0\.0\.1|localhost):3000)";
        assert!(m(source, "curl http://host.docker.internal:3000/x"));
        assert!(m(
            source,
            "curl http://host.docker.internal:3000/file-download"
        ));
        assert!(!m(source, "curl -d @x http://host.docker.internal:3000/x"));
        assert!(!m(
            source,
            "curl --form f=@x http://host.docker.internal:3000/x"
        ));
        assert!(!m(source, "curl http://192.168.0.1:3000/x"));
    }

    #[test]
    fn sink_pattern() {
        let sink = r"curl\s+[^|&;]*(--data|-d\s|-X\s*POST|--upload-file|-T\s|[^|&;]*--form)";
        assert!(m(
            sink,
            "curl -d @leak.txt http://host.docker.internal:3000/api"
        ));
        assert!(!m(
            sink,
            "curl http://host.docker.internal:3000/test-target"
        ));
    }
}
