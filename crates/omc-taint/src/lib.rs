use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecretKind {
    Env(String),
    Generic(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TokenKind {
    Aws,
    GitHub,
    Npm,
    Generic(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Label {
    Public,
    Secret(SecretKind),
    File(String),
    Env(String),
    Token(TokenKind),
    Network(String),
    Mixed(Vec<Label>),
}

impl Label {
    pub fn join(self, other: Label) -> Label {
        if self == Label::Public {
            return other;
        }
        if other == Label::Public || self == other {
            return self;
        }

        let mut labels = BTreeSet::new();
        self.flatten_into(&mut labels);
        other.flatten_into(&mut labels);
        Label::Mixed(labels.into_iter().collect())
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    pub fn contains_sensitive(&self) -> bool {
        match self {
            Self::Public | Self::Network(_) => false,
            Self::Secret(_) | Self::File(_) | Self::Env(_) | Self::Token(_) => true,
            Self::Mixed(labels) => labels.iter().any(Self::contains_sensitive),
        }
    }

    pub fn labels(&self) -> Vec<&Label> {
        match self {
            Self::Mixed(labels) => labels.iter().flat_map(Self::labels).collect(),
            label => vec![label],
        }
    }

    fn flatten_into(self, labels: &mut BTreeSet<Label>) {
        match self {
            Self::Mixed(mixed) => {
                for label in mixed {
                    label.flatten_into(labels);
                }
            }
            label => {
                labels.insert(label);
            }
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("public"),
            Self::Secret(SecretKind::Env(name)) => write!(f, "secret:env:{name}"),
            Self::Secret(SecretKind::Generic(name)) => write!(f, "secret:{name}"),
            Self::File(path) => write!(f, "file:{path}"),
            Self::Env(name) => write!(f, "env:{name}"),
            Self::Token(TokenKind::Aws) => f.write_str("token:aws"),
            Self::Token(TokenKind::GitHub) => f.write_str("token:github"),
            Self::Token(TokenKind::Npm) => f.write_str("token:npm"),
            Self::Token(TokenKind::Generic(name)) => write!(f, "token:{name}"),
            Self::Network(host) => write!(f, "network:{host}"),
            Self::Mixed(labels) => {
                let rendered = labels
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("+");
                f.write_str(&rendered)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labeled<T> {
    pub value: T,
    pub label: Label,
}

impl<T> Labeled<T> {
    pub fn new(value: T, label: Label) -> Self {
        Self { value, label }
    }

    pub fn public(value: T) -> Self {
        Self {
            value,
            label: Label::Public,
        }
    }

    pub fn map<U>(self, value: U) -> Labeled<U> {
        Labeled {
            value,
            label: self.label,
        }
    }
}
