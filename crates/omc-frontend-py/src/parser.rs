//! Recursive-descent parser for the supported Python subset.
//!
//! Builds a small AST. Every construct outside the subset is a hard
//! [`FrontendError`]; nothing is silently dropped or mis-parsed into a benign
//! shape (deny-by-default).

use crate::lexer::{Tok, Token};
use crate::FrontendError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div, // both `/` and `//` lower to integer Div in this subset
    Mod,
    Eq,
    NotEq,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Int(i64),
    Str(String),
    Bool(bool),
    /// A bare name: a local, a parameter, or an imported module alias.
    Name(String),
    /// Unary `not e`.
    Not(Box<Expr>),
    /// Unary `-e`.
    Neg(Box<Expr>),
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// `e[index]`
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
    },
    /// Attribute access `e.attr` (used to recognise capability call targets).
    Attr {
        base: Box<Expr>,
        attr: String,
    },
    /// Subscript with string key written as attribute? No — captured by Index.
    /// A call `callee(args...)`.
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    /// `[a, b, c]`
    List(Vec<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    /// `name = expr`
    Assign {
        name: String,
        value: Expr,
    },
    Return(Option<Expr>),
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        /// elif/else chain; empty if no else.
        else_body: Vec<Stmt>,
    },
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    /// An expression evaluated for effect (e.g. a capability call).
    Expr(Expr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncDef {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
}

/// A parsed import. `import requests` -> alias=requests, name=requests.
/// `from pkg import f` -> we record the bound name(s) so calls resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    /// `import name` (optionally `import name as alias`).
    Module { name: String, alias: String },
    /// `from module import names...`
    From { module: String, names: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedModule {
    pub imports: Vec<Import>,
    pub functions: Vec<FuncDef>,
}

pub fn parse(tokens: &[Token]) -> Result<ParsedModule, FrontendError> {
    Parser::new(tokens).parse_module()
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Tok {
        &self.tokens[self.pos].tok
    }

    fn line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn advance(&mut self) -> Tok {
        let tok = self.tokens[self.pos].tok.clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        tok
    }

    fn check(&self, tok: &Tok) -> bool {
        self.peek() == tok
    }

    fn eat(&mut self, tok: &Tok) -> bool {
        if self.check(tok) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, tok: &Tok, what: &str) -> Result<(), FrontendError> {
        if self.eat(tok) {
            Ok(())
        } else {
            Err(FrontendError::new(format!(
                "line {}: expected {what}, found {:?}",
                self.line(),
                self.peek()
            )))
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Tok::Newline) {
            self.advance();
        }
    }

    fn parse_module(&mut self) -> Result<ParsedModule, FrontendError> {
        let mut imports = Vec::new();
        let mut functions = Vec::new();

        self.skip_newlines();
        while !matches!(self.peek(), Tok::Eof) {
            match self.peek() {
                Tok::Import | Tok::From => imports.push(self.parse_import()?),
                Tok::Def => functions.push(self.parse_func()?),
                other => {
                    return Err(FrontendError::new(format!(
                        "line {}: only top-level `def`/`import` are supported, found {:?}",
                        self.line(),
                        other
                    )));
                }
            }
            self.skip_newlines();
        }

        if functions.is_empty() {
            return Err(FrontendError::new(
                "module defines no functions (nothing to export)",
            ));
        }
        Ok(ParsedModule { imports, functions })
    }

    fn parse_import(&mut self) -> Result<Import, FrontendError> {
        if self.eat(&Tok::Import) {
            let name = self.parse_dotted_name()?;
            let alias = if self.eat_ident("as") {
                self.expect_ident("import alias")?
            } else {
                // Alias is the first segment of a dotted name (`import a.b` binds `a`).
                name.split('.').next().unwrap_or(&name).to_owned()
            };
            self.expect(&Tok::Newline, "newline after import")?;
            return Ok(Import::Module { name, alias });
        }
        // `from module import a, b`
        self.expect(&Tok::From, "from")?;
        let module = self.parse_dotted_name()?;
        self.expect(&Tok::Import, "import")?;
        let mut names = Vec::new();
        loop {
            names.push(self.expect_ident("imported name")?);
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect(&Tok::Newline, "newline after import")?;
        Ok(Import::From { module, names })
    }

    /// A possibly-dotted module name like `urllib.request`.
    fn parse_dotted_name(&mut self) -> Result<String, FrontendError> {
        let mut name = self.expect_ident("module name")?;
        while self.eat(&Tok::Dot) {
            let seg = self.expect_ident("module name segment")?;
            name.push('.');
            name.push_str(&seg);
        }
        Ok(name)
    }

    fn eat_ident(&mut self, word: &str) -> bool {
        if let Tok::Ident(name) = self.peek() {
            if name == word {
                self.advance();
                return true;
            }
        }
        false
    }

    fn expect_ident(&mut self, what: &str) -> Result<String, FrontendError> {
        match self.peek().clone() {
            Tok::Ident(name) => {
                self.advance();
                Ok(name)
            }
            other => Err(FrontendError::new(format!(
                "line {}: expected {what}, found {:?}",
                self.line(),
                other
            ))),
        }
    }

    fn parse_func(&mut self) -> Result<FuncDef, FrontendError> {
        self.expect(&Tok::Def, "def")?;
        let name = self.expect_ident("function name")?;
        self.expect(&Tok::LParen, "(")?;
        let mut params = Vec::new();
        if !self.check(&Tok::RParen) {
            loop {
                params.push(self.expect_ident("parameter name")?);
                if !self.eat(&Tok::Comma) {
                    break;
                }
            }
        }
        self.expect(&Tok::RParen, ")")?;
        self.expect(&Tok::Colon, ":")?;
        let body = self.parse_block()?;
        Ok(FuncDef { name, params, body })
    }

    /// Parse an indented suite: NEWLINE INDENT stmt+ DEDENT.
    fn parse_block(&mut self) -> Result<Vec<Stmt>, FrontendError> {
        self.expect(&Tok::Newline, "newline before block")?;
        self.expect(&Tok::Indent, "indented block")?;
        let mut stmts = Vec::new();
        while !matches!(self.peek(), Tok::Dedent | Tok::Eof) {
            self.skip_newlines();
            if matches!(self.peek(), Tok::Dedent | Tok::Eof) {
                break;
            }
            stmts.push(self.parse_stmt()?);
            self.skip_newlines();
        }
        self.expect(&Tok::Dedent, "dedent ending block")?;
        if stmts.is_empty() {
            return Err(FrontendError::new(format!(
                "line {}: empty block (no statements)",
                self.line()
            )));
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, FrontendError> {
        match self.peek() {
            Tok::Return => {
                self.advance();
                if matches!(self.peek(), Tok::Newline) {
                    self.expect(&Tok::Newline, "newline")?;
                    Ok(Stmt::Return(None))
                } else {
                    let expr = self.parse_expr()?;
                    self.expect(&Tok::Newline, "newline after return")?;
                    Ok(Stmt::Return(Some(expr)))
                }
            }
            Tok::If => self.parse_if(),
            Tok::While => {
                self.advance();
                let cond = self.parse_expr()?;
                self.expect(&Tok::Colon, ":")?;
                let body = self.parse_block()?;
                Ok(Stmt::While { cond, body })
            }
            Tok::Ident(_) => {
                // Could be `name = expr` or an expression statement.
                // Look ahead: an assignment is `IDENT =` with nothing between.
                if matches!(self.peek(), Tok::Ident(_))
                    && self.tokens.get(self.pos + 1).map(|t| &t.tok) == Some(&Tok::Assign)
                {
                    let name = self.expect_ident("assignment target")?;
                    self.expect(&Tok::Assign, "=")?;
                    let value = self.parse_expr()?;
                    self.expect(&Tok::Newline, "newline after assignment")?;
                    Ok(Stmt::Assign { name, value })
                } else {
                    let expr = self.parse_expr()?;
                    self.expect(&Tok::Newline, "newline after expression")?;
                    Ok(Stmt::Expr(expr))
                }
            }
            other => Err(FrontendError::new(format!(
                "line {}: unsupported statement starting with {:?}",
                self.line(),
                other
            ))),
        }
    }

    fn parse_if(&mut self) -> Result<Stmt, FrontendError> {
        self.expect(&Tok::If, "if")?;
        let cond = self.parse_expr()?;
        self.expect(&Tok::Colon, ":")?;
        let then_body = self.parse_block()?;

        let else_body = if self.check(&Tok::Elif) {
            // `elif` is sugar for `else: if ...`. Re-enter via parse_if by
            // swapping the leading Elif token's role.
            self.advance(); // consume `elif`
            let elif_cond = self.parse_expr()?;
            self.expect(&Tok::Colon, ":")?;
            let elif_then = self.parse_block()?;
            let elif_else = self.parse_elif_tail()?;
            vec![Stmt::If {
                cond: elif_cond,
                then_body: elif_then,
                else_body: elif_else,
            }]
        } else if self.eat(&Tok::Else) {
            self.expect(&Tok::Colon, ":")?;
            self.parse_block()?
        } else {
            Vec::new()
        };

        Ok(Stmt::If {
            cond,
            then_body,
            else_body,
        })
    }

    /// Parse the chain after an `elif` (another elif, an else, or nothing).
    fn parse_elif_tail(&mut self) -> Result<Vec<Stmt>, FrontendError> {
        if self.check(&Tok::Elif) {
            self.advance();
            let cond = self.parse_expr()?;
            self.expect(&Tok::Colon, ":")?;
            let then_body = self.parse_block()?;
            let else_body = self.parse_elif_tail()?;
            Ok(vec![Stmt::If {
                cond,
                then_body,
                else_body,
            }])
        } else if self.eat(&Tok::Else) {
            self.expect(&Tok::Colon, ":")?;
            self.parse_block()
        } else {
            Ok(Vec::new())
        }
    }

    // ----- Expression grammar (precedence climbing) -----
    // expr      := or_expr
    // or_expr   := and_expr ('or' and_expr)*
    // and_expr  := not_expr ('and' not_expr)*
    // not_expr  := 'not' not_expr | comparison
    // comparison:= sum (cmp_op sum)?
    // sum       := term (('+'|'-') term)*
    // term      := unary (('*'|'/'|'//'|'%') unary)*
    // unary     := '-' unary | postfix
    // postfix   := primary ('(' args ')' | '[' expr ']' | '.' ident)*
    // primary   := INT | STR | True | False | name | '(' expr ')' | '[' list ']'

    fn parse_expr(&mut self) -> Result<Expr, FrontendError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, FrontendError> {
        let mut left = self.parse_and()?;
        while self.eat(&Tok::Or) {
            let right = self.parse_and()?;
            left = Expr::Binary {
                op: BinOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FrontendError> {
        let mut left = self.parse_not()?;
        while self.eat(&Tok::And) {
            let right = self.parse_not()?;
            left = Expr::Binary {
                op: BinOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, FrontendError> {
        if self.eat(&Tok::Not) {
            let inner = self.parse_not()?;
            Ok(Expr::Not(Box::new(inner)))
        } else {
            self.parse_comparison()
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, FrontendError> {
        let left = self.parse_sum()?;
        let op = match self.peek() {
            Tok::EqEq => Some(BinOp::Eq),
            Tok::NotEq => Some(BinOp::NotEq),
            Tok::Lt => Some(BinOp::Lt),
            Tok::Gt => Some(BinOp::Gt),
            Tok::Le => Some(BinOp::Le),
            Tok::Ge => Some(BinOp::Ge),
            _ => None,
        };
        if let Some(op) = op {
            self.advance();
            let right = self.parse_sum()?;
            // No chained comparisons in the subset (a < b < c is rejected).
            if matches!(
                self.peek(),
                Tok::EqEq | Tok::NotEq | Tok::Lt | Tok::Gt | Tok::Le | Tok::Ge
            ) {
                return Err(FrontendError::new(format!(
                    "line {}: chained comparisons are not supported",
                    self.line()
                )));
            }
            Ok(Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            })
        } else {
            Ok(left)
        }
    }

    fn parse_sum(&mut self) -> Result<Expr, FrontendError> {
        let mut left = self.parse_term()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_term()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_term(&mut self) -> Result<Expr, FrontendError> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash | Tok::DoubleSlash => BinOp::Div,
                Tok::Percent => BinOp::Mod,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, FrontendError> {
        if self.eat(&Tok::Minus) {
            let inner = self.parse_unary()?;
            Ok(Expr::Neg(Box::new(inner)))
        } else {
            self.parse_postfix()
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, FrontendError> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek() {
                Tok::LParen => {
                    self.advance();
                    let mut args = Vec::new();
                    if !self.check(&Tok::RParen) {
                        loop {
                            args.push(self.parse_expr()?);
                            if !self.eat(&Tok::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect(&Tok::RParen, ")")?;
                    expr = Expr::Call {
                        callee: Box::new(expr),
                        args,
                    };
                }
                Tok::LBracket => {
                    self.advance();
                    let index = self.parse_expr()?;
                    self.expect(&Tok::RBracket, "]")?;
                    expr = Expr::Index {
                        base: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                Tok::Dot => {
                    self.advance();
                    let attr = self.expect_ident("attribute name")?;
                    expr = Expr::Attr {
                        base: Box::new(expr),
                        attr,
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, FrontendError> {
        match self.peek().clone() {
            Tok::Int(value) => {
                self.advance();
                Ok(Expr::Int(value))
            }
            Tok::Str(value) => {
                self.advance();
                Ok(Expr::Str(value))
            }
            Tok::True => {
                self.advance();
                Ok(Expr::Bool(true))
            }
            Tok::False => {
                self.advance();
                Ok(Expr::Bool(false))
            }
            Tok::Ident(name) => {
                self.advance();
                Ok(Expr::Name(name))
            }
            Tok::LParen => {
                self.advance();
                let inner = self.parse_expr()?;
                self.expect(&Tok::RParen, ")")?;
                Ok(inner)
            }
            Tok::LBracket => {
                self.advance();
                let mut items = Vec::new();
                if !self.check(&Tok::RBracket) {
                    loop {
                        items.push(self.parse_expr()?);
                        if !self.eat(&Tok::Comma) {
                            break;
                        }
                    }
                }
                self.expect(&Tok::RBracket, "]")?;
                Ok(Expr::List(items))
            }
            other => Err(FrontendError::new(format!(
                "line {}: unexpected token in expression: {:?}",
                self.line(),
                other
            ))),
        }
    }
}
