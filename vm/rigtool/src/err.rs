//! Minimal error plumbing (no external error crate).

use std::fmt;

#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<E: std::error::Error> From<E> for Error {
    fn from(e: E) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Context<T> {
    fn context<S: Into<String>>(self, s: S) -> Result<T>;
    fn with_context<S: Into<String>, F: FnOnce() -> S>(self, f: F) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context<S: Into<String>>(self, s: S) -> Result<T> {
        self.map_err(|e| Error(format!("{}: {e}", s.into())))
    }
    fn with_context<S: Into<String>, F: FnOnce() -> S>(self, f: F) -> Result<T> {
        self.map_err(|e| Error(format!("{}: {e}", f().into())))
    }
}

impl<T> Context<T> for Option<T> {
    fn context<S: Into<String>>(self, s: S) -> Result<T> {
        self.ok_or_else(|| Error(s.into()))
    }
    fn with_context<S: Into<String>, F: FnOnce() -> S>(self, f: F) -> Result<T> {
        self.ok_or_else(|| Error(f().into()))
    }
}

macro_rules! bail {
    ($($t:tt)*) => { return Err($crate::err::Error(format!($($t)*))) };
}
pub(crate) use bail;
