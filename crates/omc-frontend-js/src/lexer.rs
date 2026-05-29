//! Hand-written lexer for the supported JavaScript subset.
//!
//! No external crate: this is a small, total scanner over the defined subset.
//! Anything it cannot recognise is a hard error (deny-by-default) so the parser
//! never sees, and silently drops, an unsupported construct.

use crate::FrontendError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    // literals / names
    Ident(String),
    Int(i64),
    Str(String),
    True,
    False,

    // keywords
    Function,
    Return,
    If,
    Else,
    While,
    Const,
    Let,
    Var,
    New,

    // punctuation
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Dot,
    Assign, // =

    // operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEqEq, // ===
    NeEqEq, // !==
    Lt,
    Gt,
    Le,
    Ge,
    AndAnd, // &&
    OrOr,   // ||
    Bang,   // !

    Eof,
}

pub fn lex(source: &str) -> Result<Vec<Tok>, FrontendError> {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    let mut out = Vec::new();

    while i < n {
        let c = bytes[i] as char;

        // Whitespace.
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Line comment.
        if c == '/' && i + 1 < n && bytes[i + 1] == b'/' {
            i += 2;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment.
        if c == '/' && i + 1 < n && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 >= n {
                return Err(FrontendError::new("unterminated block comment"));
            }
            i += 2;
            continue;
        }

        // String literal: single or double quoted, simple escapes only.
        if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            let mut s = String::new();
            loop {
                if i >= n {
                    return Err(FrontendError::new("unterminated string literal"));
                }
                let ch = bytes[i] as char;
                if ch == quote {
                    i += 1;
                    break;
                }
                if ch == '\\' {
                    i += 1;
                    if i >= n {
                        return Err(FrontendError::new("unterminated string escape"));
                    }
                    let esc = bytes[i] as char;
                    match esc {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        '\\' => s.push('\\'),
                        '\'' => s.push('\''),
                        '"' => s.push('"'),
                        '0' => s.push('\0'),
                        other => {
                            return Err(FrontendError::new(format!(
                                "unsupported string escape \\{other}"
                            )))
                        }
                    }
                    i += 1;
                    continue;
                }
                // Template literals and raw newlines inside a quoted string are
                // not part of the subset.
                if ch == '\n' {
                    return Err(FrontendError::new("newline inside string literal"));
                }
                s.push(ch);
                i += 1;
            }
            out.push(Tok::Str(s));
            continue;
        }

        // Number literal (non-negative integer; unary minus is a separate op).
        if c.is_ascii_digit() {
            let start = i;
            while i < n && (bytes[i] as char).is_ascii_digit() {
                i += 1;
            }
            // A '.' immediately after digits means a float, which is outside the
            // integer-only subset: fail closed rather than truncate.
            if i < n && bytes[i] == b'.' {
                return Err(FrontendError::new(
                    "floating-point literals are not in the supported subset",
                ));
            }
            let text = &source[start..i];
            let value: i64 = text
                .parse()
                .map_err(|_| FrontendError::new(format!("integer literal out of range: {text}")))?;
            out.push(Tok::Int(value));
            continue;
        }

        // Identifier / keyword.
        if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while i < n {
                let ch = bytes[i] as char;
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
                    i += 1;
                } else {
                    break;
                }
            }
            let word = &source[start..i];
            out.push(match word {
                "function" => Tok::Function,
                "return" => Tok::Return,
                "if" => Tok::If,
                "else" => Tok::Else,
                "while" => Tok::While,
                "const" => Tok::Const,
                "let" => Tok::Let,
                "var" => Tok::Var,
                "new" => Tok::New,
                "true" => Tok::True,
                "false" => Tok::False,
                other => Tok::Ident(other.to_owned()),
            });
            continue;
        }

        // Multi-char operators first, then single-char punctuation.
        macro_rules! two {
            ($a:expr, $b:expr) => {
                i + 1 < n && bytes[i] == $a && bytes[i + 1] == $b
            };
        }

        if i + 2 < n && bytes[i] == b'=' && bytes[i + 1] == b'=' && bytes[i + 2] == b'=' {
            out.push(Tok::EqEqEq);
            i += 3;
            continue;
        }
        if i + 2 < n && bytes[i] == b'!' && bytes[i + 1] == b'=' && bytes[i + 2] == b'=' {
            out.push(Tok::NeEqEq);
            i += 3;
            continue;
        }
        // `==` / `!=` are deliberately NOT accepted: the subset is strict
        // equality only, so loose equality fails closed rather than being
        // silently treated as strict.
        if two!(b'=', b'=') {
            return Err(FrontendError::new(
                "loose equality `==` is not supported; use `===`",
            ));
        }
        if two!(b'!', b'=') {
            return Err(FrontendError::new(
                "loose inequality `!=` is not supported; use `!==`",
            ));
        }
        if two!(b'<', b'=') {
            out.push(Tok::Le);
            i += 2;
            continue;
        }
        if two!(b'>', b'=') {
            out.push(Tok::Ge);
            i += 2;
            continue;
        }
        if two!(b'&', b'&') {
            out.push(Tok::AndAnd);
            i += 2;
            continue;
        }
        if two!(b'|', b'|') {
            out.push(Tok::OrOr);
            i += 2;
            continue;
        }

        let single = match c {
            '(' => Tok::LParen,
            ')' => Tok::RParen,
            '{' => Tok::LBrace,
            '}' => Tok::RBrace,
            '[' => Tok::LBracket,
            ']' => Tok::RBracket,
            ',' => Tok::Comma,
            ';' => Tok::Semi,
            '.' => Tok::Dot,
            '=' => Tok::Assign,
            '+' => Tok::Plus,
            '-' => Tok::Minus,
            '*' => Tok::Star,
            '/' => Tok::Slash,
            '%' => Tok::Percent,
            '<' => Tok::Lt,
            '>' => Tok::Gt,
            '!' => Tok::Bang,
            other => {
                return Err(FrontendError::new(format!(
                    "unexpected character '{other}' in source"
                )))
            }
        };
        out.push(single);
        i += 1;
    }

    out.push(Tok::Eof);
    Ok(out)
}
