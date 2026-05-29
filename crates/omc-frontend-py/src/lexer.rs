//! Hand-written lexer for the supported Python subset.
//!
//! Produces a flat token stream including the synthetic `Newline`, `Indent`,
//! and `Dedent` tokens that Python's significant-indentation grammar needs.
//! Anything the lexer cannot classify is a hard [`FrontendError`] — deny by
//! default, never a silent skip.

use crate::FrontendError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    // Literals / identifiers
    Int(i64),
    Str(String),
    Ident(String),
    // Keywords
    Def,
    Return,
    If,
    Elif,
    Else,
    While,
    True,
    False,
    And,
    Or,
    Not,
    Import,
    From,
    // Punctuation
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Dot,
    Assign,
    // Operators
    Plus,
    Minus,
    Star,
    Slash,       // `/`
    DoubleSlash, // `//`
    Percent,
    EqEq,
    NotEq,
    Lt,
    Gt,
    Le,
    Ge,
    // Layout
    Newline,
    Indent,
    Dedent,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

/// Tokenize `source`. Comments (`# ...`) and blank lines are discarded.
/// Indentation is tracked with an indent stack; mixing tabs and spaces in the
/// leading whitespace of a line is rejected (deny-by-default — we will not
/// guess the author's intent).
pub fn lex(source: &str) -> Result<Vec<Token>, FrontendError> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut indent_stack: Vec<usize> = vec![0];
    // Parenthesis depth: inside (), [] Python ignores newlines/indentation.
    let mut paren_depth: usize = 0;

    for (line_idx, raw_line) in source.lines().enumerate() {
        let line_no = line_idx + 1;

        if paren_depth == 0 {
            // Compute indentation only for logical-line starts.
            let (indent, rest) = measure_indent(raw_line, line_no)?;
            let trimmed = rest.trim_end();
            // Blank line or comment-only line: no layout tokens.
            if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
                lex_inline(rest, line_no, &mut tokens, &mut paren_depth)?;
                continue;
            }

            // Emit INDENT / DEDENT based on the indent stack.
            let current = *indent_stack.last().expect("indent stack never empty");
            if indent > current {
                indent_stack.push(indent);
                tokens.push(Token {
                    tok: Tok::Indent,
                    line: line_no,
                });
            } else if indent < current {
                while *indent_stack.last().expect("indent stack never empty") > indent {
                    indent_stack.pop();
                    tokens.push(Token {
                        tok: Tok::Dedent,
                        line: line_no,
                    });
                }
                if *indent_stack.last().expect("indent stack never empty") != indent {
                    return Err(FrontendError::new(format!(
                        "line {line_no}: inconsistent dedent (indentation does not match any outer level)"
                    )));
                }
            }

            lex_inline(rest, line_no, &mut tokens, &mut paren_depth)?;
        } else {
            // Continuation line inside brackets: no layout handling.
            lex_inline(raw_line, line_no, &mut tokens, &mut paren_depth)?;
        }

        // Emit a logical NEWLINE at the end of each non-continuation line that
        // produced content.
        if paren_depth == 0 {
            if let Some(last) = tokens.last() {
                if !matches!(last.tok, Tok::Newline | Tok::Indent | Tok::Dedent) {
                    tokens.push(Token {
                        tok: Tok::Newline,
                        line: line_no,
                    });
                }
            }
        }
    }

    if paren_depth != 0 {
        return Err(FrontendError::new("unterminated bracket at end of input"));
    }

    // Close out any remaining indentation, then EOF.
    let final_line = tokens.last().map(|t| t.line).unwrap_or(1);
    while indent_stack.len() > 1 {
        indent_stack.pop();
        tokens.push(Token {
            tok: Tok::Dedent,
            line: final_line,
        });
    }
    tokens.push(Token {
        tok: Tok::Eof,
        line: final_line,
    });
    Ok(tokens)
}

/// Measure leading indentation in columns. Tabs are rejected when mixed with
/// spaces; a pure-tab indent counts each tab as one column (we never need exact
/// widths, only relative ordering, and we forbid mixing so ordering is sound).
fn measure_indent(line: &str, line_no: usize) -> Result<(usize, &str), FrontendError> {
    let mut spaces = 0usize;
    let mut tabs = 0usize;
    let mut byte_idx = 0usize;
    for ch in line.chars() {
        match ch {
            ' ' => {
                spaces += 1;
                byte_idx += 1;
            }
            '\t' => {
                tabs += 1;
                byte_idx += 1;
            }
            _ => break,
        }
    }
    if spaces > 0 && tabs > 0 {
        return Err(FrontendError::new(format!(
            "line {line_no}: mixed tabs and spaces in indentation"
        )));
    }
    Ok((spaces + tabs, &line[byte_idx..]))
}

/// Lex the inline (non-layout) portion of a line into tokens.
fn lex_inline(
    line: &str,
    line_no: usize,
    tokens: &mut Vec<Token>,
    paren_depth: &mut usize,
) -> Result<(), FrontendError> {
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    let push = |tokens: &mut Vec<Token>, tok: Tok| tokens.push(Token { tok, line: line_no });

    while i < bytes.len() {
        let ch = bytes[i];
        match ch {
            ' ' | '\t' | '\r' => {
                i += 1;
            }
            '#' => break, // rest of line is a comment
            '(' => {
                push(tokens, Tok::LParen);
                *paren_depth += 1;
                i += 1;
            }
            ')' => {
                push(tokens, Tok::RParen);
                *paren_depth = paren_depth.saturating_sub(1);
                i += 1;
            }
            '[' => {
                push(tokens, Tok::LBracket);
                *paren_depth += 1;
                i += 1;
            }
            ']' => {
                push(tokens, Tok::RBracket);
                *paren_depth = paren_depth.saturating_sub(1);
                i += 1;
            }
            ':' => {
                push(tokens, Tok::Colon);
                i += 1;
            }
            ',' => {
                push(tokens, Tok::Comma);
                i += 1;
            }
            '.' => {
                push(tokens, Tok::Dot);
                i += 1;
            }
            '+' => {
                push(tokens, Tok::Plus);
                i += 1;
            }
            '-' => {
                push(tokens, Tok::Minus);
                i += 1;
            }
            '*' => {
                push(tokens, Tok::Star);
                i += 1;
            }
            '/' => {
                if bytes.get(i + 1) == Some(&'/') {
                    push(tokens, Tok::DoubleSlash);
                    i += 2;
                } else {
                    push(tokens, Tok::Slash);
                    i += 1;
                }
            }
            '%' => {
                push(tokens, Tok::Percent);
                i += 1;
            }
            '=' => {
                if bytes.get(i + 1) == Some(&'=') {
                    push(tokens, Tok::EqEq);
                    i += 2;
                } else {
                    push(tokens, Tok::Assign);
                    i += 1;
                }
            }
            '!' => {
                if bytes.get(i + 1) == Some(&'=') {
                    push(tokens, Tok::NotEq);
                    i += 2;
                } else {
                    return Err(FrontendError::new(format!(
                        "line {line_no}: unexpected '!' (only '!=' is supported)"
                    )));
                }
            }
            '<' => {
                if bytes.get(i + 1) == Some(&'=') {
                    push(tokens, Tok::Le);
                    i += 2;
                } else {
                    push(tokens, Tok::Lt);
                    i += 1;
                }
            }
            '>' => {
                if bytes.get(i + 1) == Some(&'=') {
                    push(tokens, Tok::Ge);
                    i += 2;
                } else {
                    push(tokens, Tok::Gt);
                    i += 1;
                }
            }
            '"' | '\'' => {
                let (s, consumed) = lex_string(&bytes[i..], ch, line_no)?;
                push(tokens, Tok::Str(s));
                i += consumed;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                // Reject `1.5` etc. — floats are outside the subset.
                if bytes.get(i) == Some(&'.')
                    && bytes
                        .get(i + 1)
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                {
                    return Err(FrontendError::new(format!(
                        "line {line_no}: floating-point literals are not supported"
                    )));
                }
                let text: String = bytes[start..i].iter().collect();
                let value: i64 = text.parse().map_err(|_| {
                    FrontendError::new(format!(
                        "line {line_no}: integer literal out of range: {text}"
                    ))
                })?;
                push(tokens, Tok::Int(value));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_alphanumeric() || bytes[i] == '_') {
                    i += 1;
                }
                let word: String = bytes[start..i].iter().collect();
                push(tokens, keyword_or_ident(word));
            }
            other => {
                return Err(FrontendError::new(format!(
                    "line {line_no}: unexpected character {other:?}"
                )));
            }
        }
    }
    Ok(())
}

/// Lex a single-quoted or double-quoted string starting at `bytes[0]` (the
/// quote). Returns the decoded contents and the number of chars consumed
/// (including both quotes). Only a small set of escapes is supported.
fn lex_string(
    bytes: &[char],
    quote: char,
    line_no: usize,
) -> Result<(String, usize), FrontendError> {
    let mut out = String::new();
    let mut i = 1usize; // skip opening quote
    while i < bytes.len() {
        let ch = bytes[i];
        if ch == quote {
            return Ok((out, i + 1));
        }
        if ch == '\\' {
            let next = bytes.get(i + 1).copied().ok_or_else(|| {
                FrontendError::new(format!("line {line_no}: dangling escape in string"))
            })?;
            let decoded = match next {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                '\'' => '\'',
                '"' => '"',
                '0' => '\0',
                other => {
                    return Err(FrontendError::new(format!(
                        "line {line_no}: unsupported escape \\{other}"
                    )));
                }
            };
            out.push(decoded);
            i += 2;
            continue;
        }
        out.push(ch);
        i += 1;
    }
    Err(FrontendError::new(format!(
        "line {line_no}: unterminated string literal"
    )))
}

fn keyword_or_ident(word: String) -> Tok {
    match word.as_str() {
        "def" => Tok::Def,
        "return" => Tok::Return,
        "if" => Tok::If,
        "elif" => Tok::Elif,
        "else" => Tok::Else,
        "while" => Tok::While,
        "True" => Tok::True,
        "False" => Tok::False,
        "and" => Tok::And,
        "or" => Tok::Or,
        "not" => Tok::Not,
        "import" => Tok::Import,
        "from" => Tok::From,
        _ => Tok::Ident(word),
    }
}
