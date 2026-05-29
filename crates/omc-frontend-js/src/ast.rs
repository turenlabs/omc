//! AST for the supported JavaScript subset.
//!
//! The parser produces this tree; the lowering pass consumes it. The shape is
//! deliberately small: only the constructs in the documented subset exist here,
//! so an unsupported program cannot even be represented — it fails in the
//! parser instead.

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    /// The single exported function (`module.exports = function ...`).
    pub export: FunctionDecl,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDecl {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `const`/`let` local declaration with an initializer.
    Local { name: String, value: Expr },
    /// Reassignment of an existing local: `name = expr;`.
    Assign { name: String, value: Expr },
    Return(Option<Expr>),
    If {
        cond: Expr,
        then_branch: Vec<Stmt>,
        else_branch: Vec<Stmt>,
    },
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    /// An expression evaluated for effect (e.g. a capability call), result
    /// discarded.
    Expr(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Int(i64),
    Str(String),
    Bool(bool),
    Array(Vec<Expr>),
    /// A bare identifier: a parameter, a local, or a free name resolved at
    /// lowering time.
    Ident(String),
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Not(Box<Expr>),
    /// Unary minus, e.g. `-x` or `-1`.
    Neg(Box<Expr>),
    /// `target[index]` element/member read.
    Index {
        target: Box<Expr>,
        index: Box<Expr>,
    },
    /// `target.name` member read (kept distinct from Index so the lowering pass
    /// can recognise capability member chains like `process.env`).
    Member {
        target: Box<Expr>,
        name: String,
    },
    /// A call `callee(args...)`.
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    /// `new Callee(args...)` — only `new Function(..)` is recognised, and that
    /// lowers to DynamicEval; every other `new` fails closed at lowering.
    New {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
}
