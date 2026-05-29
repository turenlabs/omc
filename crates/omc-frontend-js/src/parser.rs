//! Recursive-descent parser for the supported JavaScript subset.
//!
//! Grammar (informal):
//!   program     := "module" "." "exports" "=" funcexpr ";"?
//!                | "module" "." "exports" "=" ident ";"? funcdecl   (named form)
//!   funcexpr    := "function" ident? "(" params ")" block
//!   block       := "{" stmt* "}"
//!   stmt        := ("const"|"let"|"var") ident "=" expr ";"
//!                | "return" expr? ";"
//!                | "if" "(" expr ")" block ("else" (block | ifstmt))?
//!                | "while" "(" expr ")" block
//!                | expr ";"
//!   expr        := precedence-climbing over || && === !== < > <= >= + - * / %
//!   unary       := ("!"|"-") unary | postfix
//!   postfix     := primary ( "." ident | "[" expr "]" | "(" args ")" )*
//!   primary     := int | str | true | false | ident | "(" expr ")"
//!                | "[" args "]"  (array literal)
//!                | "new" postfix
//!
//! Anything outside this grammar is a hard `FrontendError`.

use crate::ast::{BinOp, Expr, FunctionDecl, Program, Stmt};
use crate::lexer::Tok;
use crate::FrontendError;

pub fn parse(tokens: &[Tok]) -> Result<Program, FrontendError> {
    let mut p = Parser { toks: tokens, pos: 0 };
    let program = p.parse_program()?;
    p.expect(&Tok::Eof)?;
    Ok(program)
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &Tok {
        self.toks.get(self.pos).unwrap_or(&Tok::Eof)
    }

    fn peek2(&self) -> &Tok {
        self.toks.get(self.pos + 1).unwrap_or(&Tok::Eof)
    }

    fn bump(&mut self) -> Tok {
        let t = self.toks.get(self.pos).cloned().unwrap_or(Tok::Eof);
        self.pos += 1;
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == t {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Tok) -> Result<(), FrontendError> {
        if self.peek() == t {
            self.pos += 1;
            Ok(())
        } else {
            Err(FrontendError::new(format!(
                "expected {t:?}, found {:?}",
                self.peek()
            )))
        }
    }

    fn expect_ident(&mut self) -> Result<String, FrontendError> {
        match self.bump() {
            Tok::Ident(name) => Ok(name),
            other => Err(FrontendError::new(format!(
                "expected identifier, found {other:?}"
            ))),
        }
    }

    // ---- top level --------------------------------------------------------

    fn parse_program(&mut self) -> Result<Program, FrontendError> {
        // Only the `module.exports = function ...` export form is supported.
        // `exports.foo = ...` and bare `function` declarations are out of the
        // subset and fail closed here.
        self.expect_module_exports_lhs()?;
        self.expect(&Tok::Assign)?;
        let export = self.parse_function_expr()?;
        // Optional trailing semicolon.
        self.eat(&Tok::Semi);
        Ok(Program { export })
    }

    fn expect_module_exports_lhs(&mut self) -> Result<(), FrontendError> {
        match self.peek() {
            Tok::Ident(name) if name == "module" => {
                self.bump();
                self.expect(&Tok::Dot)?;
                let prop = self.expect_ident()?;
                if prop != "exports" {
                    return Err(FrontendError::new(format!(
                        "only `module.exports = function...` is supported, found `module.{prop}`"
                    )));
                }
                Ok(())
            }
            other => Err(FrontendError::new(format!(
                "package must start with `module.exports = function...`, found {other:?}"
            ))),
        }
    }

    fn parse_function_expr(&mut self) -> Result<FunctionDecl, FrontendError> {
        self.expect(&Tok::Function)?;
        // Optional function name.
        let name = if let Tok::Ident(n) = self.peek() {
            let n = n.clone();
            self.bump();
            n
        } else {
            "default".to_owned()
        };
        self.expect(&Tok::LParen)?;
        let mut params = Vec::new();
        if !self.eat(&Tok::RParen) {
            loop {
                params.push(self.expect_ident()?);
                if self.eat(&Tok::Comma) {
                    continue;
                }
                self.expect(&Tok::RParen)?;
                break;
            }
        }
        let body = self.parse_block()?;
        Ok(FunctionDecl { name, params, body })
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>, FrontendError> {
        self.expect(&Tok::LBrace)?;
        let mut stmts = Vec::new();
        while self.peek() != &Tok::RBrace {
            if self.peek() == &Tok::Eof {
                return Err(FrontendError::new("unterminated block"));
            }
            stmts.push(self.parse_stmt()?);
        }
        self.expect(&Tok::RBrace)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, FrontendError> {
        match self.peek() {
            Tok::Const | Tok::Let | Tok::Var => {
                self.bump();
                let name = self.expect_ident()?;
                self.expect(&Tok::Assign)?;
                let value = self.parse_expr()?;
                self.expect(&Tok::Semi)?;
                Ok(Stmt::Local { name, value })
            }
            Tok::Return => {
                self.bump();
                if self.eat(&Tok::Semi) {
                    return Ok(Stmt::Return(None));
                }
                let value = self.parse_expr()?;
                self.expect(&Tok::Semi)?;
                Ok(Stmt::Return(Some(value)))
            }
            Tok::If => self.parse_if(),
            Tok::While => {
                self.bump();
                self.expect(&Tok::LParen)?;
                let cond = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                let body = self.parse_block()?;
                Ok(Stmt::While { cond, body })
            }
            Tok::Function => Err(FrontendError::new(
                "nested function declarations are not in the supported subset",
            )),
            // `name = expr;` reassignment of an existing local.
            Tok::Ident(_) if self.peek2() == &Tok::Assign => {
                let name = self.expect_ident()?;
                self.expect(&Tok::Assign)?;
                let value = self.parse_expr()?;
                self.expect(&Tok::Semi)?;
                Ok(Stmt::Assign { name, value })
            }
            _ => {
                let expr = self.parse_expr()?;
                self.expect(&Tok::Semi)?;
                Ok(Stmt::Expr(expr))
            }
        }
    }

    fn parse_if(&mut self) -> Result<Stmt, FrontendError> {
        self.expect(&Tok::If)?;
        self.expect(&Tok::LParen)?;
        let cond = self.parse_expr()?;
        self.expect(&Tok::RParen)?;
        let then_branch = self.parse_block()?;
        let else_branch = if self.eat(&Tok::Else) {
            if self.peek() == &Tok::If {
                // `else if` — represent as a single nested if statement.
                vec![self.parse_if()?]
            } else {
                self.parse_block()?
            }
        } else {
            Vec::new()
        };
        Ok(Stmt::If {
            cond,
            then_branch,
            else_branch,
        })
    }

    // ---- expressions (precedence climbing) --------------------------------

    fn parse_expr(&mut self) -> Result<Expr, FrontendError> {
        self.parse_bin(0)
    }

    /// Returns (binding power, op) for the current token if it is a binary op.
    fn binop_of(tok: &Tok) -> Option<(u8, BinOp)> {
        Some(match tok {
            Tok::OrOr => (1, BinOp::Or),
            Tok::AndAnd => (2, BinOp::And),
            Tok::EqEqEq => (3, BinOp::Eq),
            Tok::NeEqEq => (3, BinOp::Ne),
            Tok::Lt => (4, BinOp::Lt),
            Tok::Gt => (4, BinOp::Gt),
            Tok::Le => (4, BinOp::Le),
            Tok::Ge => (4, BinOp::Ge),
            Tok::Plus => (5, BinOp::Add),
            Tok::Minus => (5, BinOp::Sub),
            Tok::Star => (6, BinOp::Mul),
            Tok::Slash => (6, BinOp::Div),
            Tok::Percent => (6, BinOp::Mod),
            _ => return None,
        })
    }

    fn parse_bin(&mut self, min_bp: u8) -> Result<Expr, FrontendError> {
        let mut left = self.parse_unary()?;
        while let Some((bp, op)) = Self::binop_of(self.peek()) {
            if bp < min_bp {
                break;
            }
            self.bump();
            // Left-associative: parse the right side with bp+1.
            let right = self.parse_bin(bp + 1)?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, FrontendError> {
        match self.peek() {
            Tok::Bang => {
                self.bump();
                Ok(Expr::Not(Box::new(self.parse_unary()?)))
            }
            Tok::Minus => {
                self.bump();
                Ok(Expr::Neg(Box::new(self.parse_unary()?)))
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, FrontendError> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek() {
                Tok::Dot => {
                    self.bump();
                    let name = self.expect_ident()?;
                    expr = Expr::Member {
                        target: Box::new(expr),
                        name,
                    };
                }
                Tok::LBracket => {
                    self.bump();
                    let index = self.parse_expr()?;
                    self.expect(&Tok::RBracket)?;
                    expr = Expr::Index {
                        target: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                Tok::LParen => {
                    let args = self.parse_args()?;
                    expr = Expr::Call {
                        callee: Box::new(expr),
                        args,
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>, FrontendError> {
        self.expect(&Tok::LParen)?;
        let mut args = Vec::new();
        if self.eat(&Tok::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.parse_expr()?);
            if self.eat(&Tok::Comma) {
                continue;
            }
            self.expect(&Tok::RParen)?;
            break;
        }
        Ok(args)
    }

    fn parse_primary(&mut self) -> Result<Expr, FrontendError> {
        match self.bump() {
            Tok::Int(value) => Ok(Expr::Int(value)),
            Tok::Str(value) => Ok(Expr::Str(value)),
            Tok::True => Ok(Expr::Bool(true)),
            Tok::False => Ok(Expr::Bool(false)),
            Tok::Ident(name) => Ok(Expr::Ident(name)),
            Tok::LParen => {
                let expr = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                Ok(expr)
            }
            Tok::LBracket => {
                let mut elems = Vec::new();
                if !self.eat(&Tok::RBracket) {
                    loop {
                        elems.push(self.parse_expr()?);
                        if self.eat(&Tok::Comma) {
                            continue;
                        }
                        self.expect(&Tok::RBracket)?;
                        break;
                    }
                }
                Ok(Expr::Array(elems))
            }
            Tok::New => {
                // `new Callee(args)`. Parse the callee as a postfix without the
                // trailing call, then require an argument list.
                let callee = self.parse_primary()?;
                // Allow member access on the constructor (e.g. `new a.B`).
                let callee = self.continue_member(callee)?;
                let args = if self.peek() == &Tok::LParen {
                    self.parse_args()?
                } else {
                    Vec::new()
                };
                Ok(Expr::New {
                    callee: Box::new(callee),
                    args,
                })
            }
            other => Err(FrontendError::new(format!(
                "unexpected token in expression: {other:?}"
            ))),
        }
    }

    /// After `new`, allow `.name` member chains on the constructor reference.
    fn continue_member(&mut self, mut expr: Expr) -> Result<Expr, FrontendError> {
        while self.peek() == &Tok::Dot {
            self.bump();
            let name = self.expect_ident()?;
            expr = Expr::Member {
                target: Box::new(expr),
                name,
            };
        }
        Ok(expr)
    }
}
