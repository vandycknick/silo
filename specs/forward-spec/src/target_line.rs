use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::{Address, MAX_TARGET_LINE_BYTES};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token([u8; 16]);

impl Token {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Token(..)")
    }
}

impl fmt::Display for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 16]> for Token {
    fn from(value: [u8; 16]) -> Self {
        Self::new(value)
    }
}

impl From<Token> for [u8; 16] {
    fn from(value: Token) -> Self {
        value.into_bytes()
    }
}

impl TryFrom<&[u8]> for Token {
    type Error = TokenError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes =
            <[u8; 16]>::try_from(value).map_err(|_| TokenError::InvalidByteLength(value.len()))?;
        Ok(Self::new(bytes))
    }
}

impl FromStr for Token {
    type Err = TokenError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(TokenError::InvalidHex(value.to_owned()));
        }
        let mut bytes = [0_u8; 16];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TokenError {
    #[error("forward token must be exactly 32 lowercase hexadecimal characters, not {0:?}")]
    InvalidHex(String),
    #[error("forward token must contain exactly 16 bytes, not {0}")]
    InvalidByteLength(usize),
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetLine {
    Address(Address),
    Token(Token),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Ok,
    Err(ErrReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrReason {
    Invalid,
    Refused,
    Unreachable,
    NotFound,
    Permission,
    Timeout,
    Unsupported,
    Capacity,
}

impl ErrReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
            Self::NotFound => "not-found",
            Self::Permission => "permission",
            Self::Timeout => "timeout",
            Self::Unsupported => "unsupported",
            Self::Capacity => "capacity",
        }
    }
}

impl fmt::Display for ErrReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ErrReason {
    type Err = TargetLineError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "invalid" => Ok(Self::Invalid),
            "refused" => Ok(Self::Refused),
            "unreachable" => Ok(Self::Unreachable),
            "not-found" => Ok(Self::NotFound),
            "permission" => Ok(Self::Permission),
            "timeout" => Ok(Self::Timeout),
            "unsupported" => Ok(Self::Unsupported),
            "capacity" => Ok(Self::Capacity),
            _ => Err(TargetLineError::InvalidReply(value.as_bytes().to_vec())),
        }
    }
}

pub fn encode_connect(target: &TargetLine) -> Vec<u8> {
    let target = match target {
        TargetLine::Address(address) => address.to_string(),
        TargetLine::Token(token) => token.to_string(),
    };
    format!("CONNECT {target}\n").into_bytes()
}

pub fn parse_connect(line: &[u8]) -> Result<TargetLine, TargetLineError> {
    validate_complete_line(line)?;
    let target = line
        .strip_prefix(b"CONNECT ")
        .and_then(|value| value.strip_suffix(b"\n"))
        .ok_or_else(|| TargetLineError::InvalidConnect(line.to_vec()))?;
    let target = std::str::from_utf8(target).map_err(|_| TargetLineError::InvalidUtf8)?;
    if target.starts_with("tcp:") || target.starts_with("unix:") {
        return target
            .parse()
            .map(TargetLine::Address)
            .map_err(|_| TargetLineError::InvalidTarget(target.to_owned()));
    }
    target
        .parse()
        .map(TargetLine::Token)
        .map_err(|_| TargetLineError::InvalidTarget(target.to_owned()))
}

pub const fn encode_reply(reply: &Reply) -> &'static [u8] {
    match reply {
        Reply::Ok => b"OK\n",
        Reply::Err(ErrReason::Invalid) => b"ERR invalid\n",
        Reply::Err(ErrReason::Refused) => b"ERR refused\n",
        Reply::Err(ErrReason::Unreachable) => b"ERR unreachable\n",
        Reply::Err(ErrReason::NotFound) => b"ERR not-found\n",
        Reply::Err(ErrReason::Permission) => b"ERR permission\n",
        Reply::Err(ErrReason::Timeout) => b"ERR timeout\n",
        Reply::Err(ErrReason::Unsupported) => b"ERR unsupported\n",
        Reply::Err(ErrReason::Capacity) => b"ERR capacity\n",
    }
}

pub fn parse_reply(line: &[u8]) -> Result<Reply, TargetLineError> {
    validate_complete_line(line)?;
    if line == b"OK\n" {
        return Ok(Reply::Ok);
    }
    let reason = line
        .strip_prefix(b"ERR ")
        .and_then(|value| value.strip_suffix(b"\n"))
        .ok_or_else(|| TargetLineError::InvalidReply(line.to_vec()))?;
    let reason = std::str::from_utf8(reason).map_err(|_| TargetLineError::InvalidUtf8)?;
    Ok(Reply::Err(reason.parse()?))
}

fn validate_complete_line(line: &[u8]) -> Result<(), TargetLineError> {
    if line.len() > MAX_TARGET_LINE_BYTES {
        return Err(TargetLineError::TooLong(line.len()));
    }
    if !line.ends_with(b"\n") || line[..line.len().saturating_sub(1)].contains(&b'\n') {
        return Err(TargetLineError::MissingOrExtraNewline);
    }
    if line.contains(&b'\r') {
        return Err(TargetLineError::CarriageReturn);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TargetLineError {
    #[error("target line is {0} bytes; maximum is {MAX_TARGET_LINE_BYTES}")]
    TooLong(usize),
    #[error("target line must contain exactly one trailing newline")]
    MissingOrExtraNewline,
    #[error("target line must not contain a carriage return")]
    CarriageReturn,
    #[error("target line is not UTF-8")]
    InvalidUtf8,
    #[error("invalid CONNECT line {0:?}")]
    InvalidConnect(Vec<u8>),
    #[error("invalid CONNECT target {0:?}")]
    InvalidTarget(String),
    #[error("invalid reply line {0:?}")]
    InvalidReply(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use crate::{
        encode_connect, encode_reply, parse_connect, parse_reply, ErrReason, Reply, TargetLine,
        Token,
    };

    #[test]
    fn connect_address_lines_round_trip() {
        for line in [
            b"CONNECT tcp:127.0.0.1:80\n".as_slice(),
            b"CONNECT unix:/var/run/docker.sock\n".as_slice(),
        ] {
            let target = parse_connect(line).unwrap();
            assert_eq!(encode_connect(&target), line);
            assert!(matches!(target, TargetLine::Address(_)));
        }
    }

    #[test]
    fn token_is_lowercase_hex_and_redacted() {
        let token = Token::new([0xab; 16]);
        assert_eq!(token.to_string(), "abababababababababababababababab");
        assert_eq!(token.to_string().parse::<Token>().unwrap(), token);
        assert_eq!(format!("{token:?}"), "Token(..)");
        let line = encode_connect(&TargetLine::Token(token));
        assert_eq!(parse_connect(&line).unwrap(), TargetLine::Token(token));
    }

    #[test]
    fn malformed_connect_lines_are_rejected() {
        let token31 = format!("CONNECT {}\n", "a".repeat(31));
        let token33 = format!("CONNECT {}\n", "a".repeat(33));
        let uppercase = format!("CONNECT {}\n", "A".repeat(32));
        let oversized = format!("CONNECT unix:/{}\n", "a".repeat(498));
        for line in [
            token31.as_bytes(),
            token33.as_bytes(),
            uppercase.as_bytes(),
            b"CONNECT tcp:80",
            b"CONNECT tcp:80\r\n",
            oversized.as_bytes(),
            b"CONNECT  tcp:80\n",
            b"CONNECT host:tcp:80\n",
        ] {
            assert!(parse_connect(line).is_err(), "accepted {line:?}");
        }
        assert_eq!(oversized.len(), 513);
    }

    #[test]
    fn every_reply_round_trips() {
        let replies = [
            Reply::Ok,
            Reply::Err(ErrReason::Invalid),
            Reply::Err(ErrReason::Refused),
            Reply::Err(ErrReason::Unreachable),
            Reply::Err(ErrReason::NotFound),
            Reply::Err(ErrReason::Permission),
            Reply::Err(ErrReason::Timeout),
            Reply::Err(ErrReason::Unsupported),
            Reply::Err(ErrReason::Capacity),
        ];
        for reply in replies {
            assert_eq!(parse_reply(encode_reply(&reply)).unwrap(), reply);
        }
        for line in [b"ERR bogus\n".as_slice(), b"OK \n", b"OK\r\n", b"OK"] {
            assert!(parse_reply(line).is_err());
        }
    }
}
