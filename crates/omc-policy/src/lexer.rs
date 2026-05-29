//! Hand-written lexer for the `omc.policy` DSL.
//!
//! No external crate: this is a small, total scanner over the defined grammar.
//! Every token carries its 1-based line/column so the parser can report precise
//! locations. Anything it cannot recognise is a hard [`PolicyError`]
//! (deny-by-default) so a malformed policy is never silently accepted.

use crate::PolicyError;

/// A lexical token kind. Keywords are kept as a single `Ident` and disambiguated
/// by the parser against the grammar position, except for the structural tokens
/// (`{`, `}`, `,`, `->`) and the version-constraint operators, which are
/// punctuation here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// A bare identifier or keyword (`default`, `package`, `allow`, `env`, ...).
    Ident(String),
    /// A quoted string literal (already unescaped).
    Str(String),
    LBrace,
    RBrace,
    Comma,
    /// `->`
    Arrow,
    /// A version-constraint operator: `==`, `>=`, `>`, `<=`, `<`, `^`, `~`.
    VersionOp(VersionOpTok),
    Eof,
}

/// The raw version-constraint operator tokens, before grammar interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOpTok {
    EqEq,
    Ge,
    Gt,
    Le,
    Lt,
    Caret,
    Tilde,
}

/// A token together with its source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned {
    pub tok: Tok,
    pub line: usize,
    pub col: usize,
}

/// Lex `source` into a stream of spanned tokens, terminated by [`Tok::Eof`].
pub fn lex(source: &str) -> Result<Vec<Spanned>, PolicyError> {
    let bytes = source.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    // 1-based line/column tracking.
    let mut line = 1usize;
    let mut col = 1usize;
    let mut out = Vec::new();

    // Advance one byte, maintaining line/col. Newlines reset the column.
    macro_rules! advance {
        () => {{
            if bytes[i] == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            i += 1;
        }};
    }

    while i < n {
        let c = bytes[i] as char;

        // Whitespace.
        if c.is_ascii_whitespace() {
            advance!();
            continue;
        }

        // Line comment: `# ...` to end of line.
        if c == '#' {
            while i < n && bytes[i] != b'\n' {
                advance!();
            }
            continue;
        }

        // Capture the start position of this token for its span.
        let tok_line = line;
        let tok_col = col;

        // String literal: double or single quoted, simple escapes only.
        if c == '"' || c == '\'' {
            let quote = bytes[i];
            advance!();
            let mut s = String::new();
            loop {
                if i >= n {
                    return Err(PolicyError::new(
                        "unterminated string literal",
                        tok_line,
                        tok_col,
                    ));
                }
                let ch = bytes[i];
                if ch == quote {
                    advance!();
                    break;
                }
                if ch == b'\n' {
                    return Err(PolicyError::new("newline inside string literal", line, col));
                }
                if ch == b'\\' {
                    advance!();
                    if i >= n {
                        return Err(PolicyError::new("unterminated string escape", line, col));
                    }
                    let esc = bytes[i] as char;
                    match esc {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        '\\' => s.push('\\'),
                        '\'' => s.push('\''),
                        '"' => s.push('"'),
                        other => {
                            return Err(PolicyError::new(
                                format!("unsupported string escape \\{other}"),
                                line,
                                col,
                            ))
                        }
                    }
                    advance!();
                    continue;
                }
                s.push(ch as char);
                advance!();
            }
            out.push(Spanned {
                tok: Tok::Str(s),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }

        // Structural punctuation and multi-char operators.
        if c == '-' && i + 1 < n && bytes[i + 1] == b'>' {
            advance!();
            advance!();
            out.push(Spanned {
                tok: Tok::Arrow,
                line: tok_line,
                col: tok_col,
            });
            continue;
        }
        if c == '=' && i + 1 < n && bytes[i + 1] == b'=' {
            advance!();
            advance!();
            out.push(Spanned {
                tok: Tok::VersionOp(VersionOpTok::EqEq),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }
        if c == '>' && i + 1 < n && bytes[i + 1] == b'=' {
            advance!();
            advance!();
            out.push(Spanned {
                tok: Tok::VersionOp(VersionOpTok::Ge),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }
        if c == '<' && i + 1 < n && bytes[i + 1] == b'=' {
            advance!();
            advance!();
            out.push(Spanned {
                tok: Tok::VersionOp(VersionOpTok::Le),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }

        let single = match c {
            '{' => Some(Tok::LBrace),
            '}' => Some(Tok::RBrace),
            ',' => Some(Tok::Comma),
            '>' => Some(Tok::VersionOp(VersionOpTok::Gt)),
            '<' => Some(Tok::VersionOp(VersionOpTok::Lt)),
            '^' => Some(Tok::VersionOp(VersionOpTok::Caret)),
            '~' => Some(Tok::VersionOp(VersionOpTok::Tilde)),
            _ => None,
        };
        if let Some(tok) = single {
            advance!();
            out.push(Spanned {
                tok,
                line: tok_line,
                col: tok_col,
            });
            continue;
        }

        // Identifier / keyword / bareversion: starts with a letter, `_`, or a
        // digit; may contain alphanumerics plus the punctuation that appears in
        // keywords and bare version numbers (`.`, `-`, `_`). This lets
        // `allow-sensitive` and a bareversion like `12.0.0` each lex as a single
        // identifier; the parser decides which is grammatical where.
        if is_ident_start(c) {
            let start = i;
            while i < n && is_ident_continue(bytes[i] as char) {
                advance!();
            }
            let word = source[start..i].to_owned();
            out.push(Spanned {
                tok: Tok::Ident(word),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }

        // Anything else is a hard error: fail closed.
        return Err(PolicyError::new(
            format!("unexpected character '{c}'"),
            tok_line,
            tok_col,
        ));
    }

    out.push(Spanned {
        tok: Tok::Eof,
        line,
        col,
    });
    Ok(out)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}
