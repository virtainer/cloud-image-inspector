//! One error type for every layer. Images are hostile input, so "the bytes do not
//! make sense" (`Corrupt`) is an ordinary outcome, never a panic.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The data violates its own format.
    Corrupt(String),
    /// Valid, but uses a feature this tool deliberately does not read.
    Unsupported(String),
    /// A bound that protects the inspector (size, depth, count) was hit.
    Limit(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Corrupt(m) => write!(f, "corrupt: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Limit(m) => write!(f, "limit exceeded: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub fn corrupt<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Corrupt(msg.into()))
}

pub fn unsupported<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Unsupported(msg.into()))
}

pub fn limit<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Limit(msg.into()))
}
