//! PostgreSQL wire protocol v3: framing, parsers for the messages lokaj inspects and builders
//! for the messages it originates. Parsers mirror the server's `pq_getmsg*` helpers, including
//! the rule that a message body is consumed exactly, so lokaj and the server never read the same
//! bytes differently.

use bytes::{BufMut, BytesMut};

pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const GSSENC_REQUEST_CODE: i32 = 80877104;
pub const CANCEL_REQUEST_CODE: i32 = 80877102;
/// The bound PostgreSQL applies to startup packets (`MAX_STARTUP_PACKET_LENGTH`).
pub const MAX_STARTUP_PACKET: usize = 10_000;
/// The bound PostgreSQL applies to a cancel key in protocol 3.2.
const MAX_CANCEL_KEY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid message length {0}")]
    InvalidLength(i64),
    #[error("message of {0} bytes exceeds the size limit")]
    TooLarge(usize),
    #[error("malformed {0} message")]
    Malformed(&'static str),
    #[error("unsupported frontend protocol {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("invalid UTF-8 in {0} message")]
    InvalidUtf8(&'static str),
}

struct Reader<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, what }
    }

    fn malformed(&self) -> ProtocolError {
        ProtocolError::Malformed(self.what)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        if self.buf.len() < n {
            return Err(self.malformed());
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.bytes(1)?[0])
    }

    fn i16(&mut self) -> Result<i16, ProtocolError> {
        let b = self.bytes(2)?;
        Ok(i16::from_be_bytes([b[0], b[1]]))
    }

    fn i32(&mut self) -> Result<i32, ProtocolError> {
        let b = self.bytes(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn cbytes(&mut self) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| self.malformed())?;
        let s = &self.buf[..end];
        self.buf = &self.buf[end + 1..];
        Ok(s)
    }

    fn cstr(&mut self) -> Result<&'a str, ProtocolError> {
        let what = self.what;
        std::str::from_utf8(self.cbytes()?).map_err(|_| ProtocolError::InvalidUtf8(what))
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(self.malformed())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Startup phase (frontend)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPacket {
    SslRequest,
    GssEncRequest,
    Cancel {
        process_id: i32,
        secret: Vec<u8>,
    },
    Startup {
        minor: u16,
        params: Vec<(String, String)>,
    },
}

/// Total length of a startup-phase packet, read from its length prefix (which counts itself).
pub fn startup_packet_len(prefix: [u8; 4]) -> Result<usize, ProtocolError> {
    let len = i32::from_be_bytes(prefix);
    if len < 8 || len as usize > MAX_STARTUP_PACKET {
        return Err(ProtocolError::InvalidLength(len.into()));
    }
    Ok(len as usize)
}

/// Parses a startup-phase packet body: everything after the length prefix.
pub fn parse_startup_packet(body: &[u8]) -> Result<StartupPacket, ProtocolError> {
    let mut r = Reader::new(body, "startup");
    let code = r.i32()?;
    match code {
        SSL_REQUEST_CODE => {
            r.finish()?;
            Ok(StartupPacket::SslRequest)
        }
        GSSENC_REQUEST_CODE => {
            r.finish()?;
            Ok(StartupPacket::GssEncRequest)
        }
        CANCEL_REQUEST_CODE => {
            let process_id = r.i32()?;
            let secret = r.rest();
            if secret.len() < 4 || secret.len() > MAX_CANCEL_KEY {
                return Err(ProtocolError::Malformed("cancel request"));
            }
            Ok(StartupPacket::Cancel {
                process_id,
                secret: secret.to_vec(),
            })
        }
        _ => {
            let code = code as u32;
            let major = (code >> 16) as u16;
            let minor = (code & 0xffff) as u16;
            if major != 3 {
                return Err(ProtocolError::UnsupportedVersion { major, minor });
            }
            let mut params = Vec::new();
            loop {
                let name = r.cstr()?;
                if name.is_empty() {
                    break;
                }
                let value = r.cstr()?;
                params.push((name.to_owned(), value.to_owned()));
            }
            r.finish()?;
            Ok(StartupPacket::Startup { minor, params })
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Regular messages: framing
// ---------------------------------------------------------------------------------------------

/// Tag and body length of the message header at the start of `buf`, if 5 bytes are buffered.
pub fn header_at(buf: &[u8]) -> Result<Option<(u8, usize)>, ProtocolError> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if len < 4 {
        return Err(ProtocolError::InvalidLength(len.into()));
    }
    Ok(Some((buf[0], len as usize - 4)))
}

/// Tag and total length (header included) of the message at the start of `buf`, once it is
/// fully buffered. Fails as soon as the header announces more than `max_len` bytes.
pub fn frame_at(buf: &[u8], max_len: usize) -> Result<Option<(u8, usize)>, ProtocolError> {
    let Some((tag, body_len)) = header_at(buf)? else {
        return Ok(None);
    };
    let total = body_len + 5;
    if total > max_len {
        return Err(ProtocolError::TooLarge(total));
    }
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((tag, total)))
}

// ---------------------------------------------------------------------------------------------
// Regular messages: frontend
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Statement,
    Portal,
}

/// A password, kept out of `Debug` output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Redacted<'a>(pub &'a str);

impl std::fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontendMessage<'a> {
    Query {
        sql: &'a str,
    },
    Parse {
        statement: &'a str,
        sql: &'a str,
    },
    Bind {
        portal: &'a str,
        statement: &'a str,
    },
    Describe {
        target: Target,
        name: &'a str,
    },
    Execute {
        portal: &'a str,
    },
    Close {
        target: Target,
        name: &'a str,
    },
    Sync,
    Flush,
    Terminate,
    /// `PasswordMessage`; only valid while the client authenticates.
    Password {
        password: Redacted<'a>,
    },
    FunctionCall,
    CopyData,
    CopyDone,
    CopyFail,
    Unknown {
        tag: u8,
    },
}

fn target(r: &mut Reader<'_>) -> Result<Target, ProtocolError> {
    match r.u8()? {
        b'S' => Ok(Target::Statement),
        b'P' => Ok(Target::Portal),
        _ => Err(r.malformed()),
    }
}

/// Parses a frontend message body. Only the fields lokaj needs are decoded; the rest of `Bind`
/// is validated by the server.
pub fn parse_frontend(tag: u8, body: &[u8]) -> Result<FrontendMessage<'_>, ProtocolError> {
    match tag {
        b'Q' => {
            let mut r = Reader::new(body, "Query");
            let sql = r.cstr()?;
            r.finish()?;
            Ok(FrontendMessage::Query { sql })
        }
        b'P' => {
            let mut r = Reader::new(body, "Parse");
            let statement = r.cstr()?;
            let sql = r.cstr()?;
            let param_count = r.i16()?;
            if param_count < 0 {
                return Err(r.malformed());
            }
            r.bytes(param_count as usize * 4)?;
            r.finish()?;
            Ok(FrontendMessage::Parse { statement, sql })
        }
        b'B' => {
            let mut r = Reader::new(body, "Bind");
            let portal = r.cstr()?;
            let statement = r.cstr()?;
            Ok(FrontendMessage::Bind { portal, statement })
        }
        b'D' => {
            let mut r = Reader::new(body, "Describe");
            let target = target(&mut r)?;
            let name = r.cstr()?;
            r.finish()?;
            Ok(FrontendMessage::Describe { target, name })
        }
        b'E' => {
            let mut r = Reader::new(body, "Execute");
            let portal = r.cstr()?;
            r.i32()?;
            r.finish()?;
            Ok(FrontendMessage::Execute { portal })
        }
        b'C' => {
            let mut r = Reader::new(body, "Close");
            let target = target(&mut r)?;
            let name = r.cstr()?;
            r.finish()?;
            Ok(FrontendMessage::Close { target, name })
        }
        b'S' | b'H' | b'X' => {
            Reader::new(body, "Sync/Flush/Terminate").finish()?;
            Ok(match tag {
                b'S' => FrontendMessage::Sync,
                b'H' => FrontendMessage::Flush,
                _ => FrontendMessage::Terminate,
            })
        }
        b'p' => {
            let mut r = Reader::new(body, "PasswordMessage");
            let password = Redacted(r.cstr()?);
            r.finish()?;
            Ok(FrontendMessage::Password { password })
        }
        b'F' => Ok(FrontendMessage::FunctionCall),
        b'd' => Ok(FrontendMessage::CopyData),
        b'c' => Ok(FrontendMessage::CopyDone),
        b'f' => Ok(FrontendMessage::CopyFail),
        tag => Ok(FrontendMessage::Unknown { tag }),
    }
}

// ---------------------------------------------------------------------------------------------
// Regular messages: backend
// ---------------------------------------------------------------------------------------------

pub mod tag {
    pub const AUTHENTICATION: u8 = b'R';
    pub const BACKEND_KEY_DATA: u8 = b'K';
    pub const BIND_COMPLETE: u8 = b'2';
    pub const CLOSE_COMPLETE: u8 = b'3';
    pub const COMMAND_COMPLETE: u8 = b'C';
    pub const COPY_BOTH_RESPONSE: u8 = b'W';
    pub const COPY_DATA: u8 = b'd';
    pub const COPY_DONE: u8 = b'c';
    pub const COPY_IN_RESPONSE: u8 = b'G';
    pub const COPY_OUT_RESPONSE: u8 = b'H';
    pub const DATA_ROW: u8 = b'D';
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
    pub const ERROR_RESPONSE: u8 = b'E';
    pub const FUNCTION_CALL_RESPONSE: u8 = b'V';
    pub const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
    pub const NO_DATA: u8 = b'n';
    pub const NOTICE_RESPONSE: u8 = b'N';
    pub const NOTIFICATION_RESPONSE: u8 = b'A';
    pub const PARAMETER_DESCRIPTION: u8 = b't';
    pub const PARAMETER_STATUS: u8 = b'S';
    pub const PARSE_COMPLETE: u8 = b'1';
    pub const PORTAL_SUSPENDED: u8 = b's';
    pub const READY_FOR_QUERY: u8 = b'Z';
    pub const ROW_DESCRIPTION: u8 = b'T';
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Idle,
    InTransaction,
    Failed,
}

impl TxStatus {
    pub fn byte(self) -> u8 {
        match self {
            TxStatus::Idle => b'I',
            TxStatus::InTransaction => b'T',
            TxStatus::Failed => b'E',
        }
    }
}

pub fn parse_ready_for_query(body: &[u8]) -> Result<TxStatus, ProtocolError> {
    let mut r = Reader::new(body, "ReadyForQuery");
    let status = match r.u8()? {
        b'I' => TxStatus::Idle,
        b'T' => TxStatus::InTransaction,
        b'E' => TxStatus::Failed,
        _ => return Err(r.malformed()),
    };
    r.finish()?;
    Ok(status)
}

pub fn parse_parameter_status(body: &[u8]) -> Result<(&str, &str), ProtocolError> {
    let mut r = Reader::new(body, "ParameterStatus");
    let name = r.cstr()?;
    let value = r.cstr()?;
    r.finish()?;
    Ok((name, value))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorFields {
    /// Non-localized severity (`V`), falling back to the localized one (`S`).
    pub severity: String,
    pub code: String,
    pub message: String,
}

impl ErrorFields {
    pub fn is_fatal(&self) -> bool {
        self.severity == "FATAL" || self.severity == "PANIC"
    }
}

pub fn parse_error_response(body: &[u8]) -> Result<ErrorFields, ProtocolError> {
    let mut r = Reader::new(body, "ErrorResponse");
    let mut localized = None;
    let mut severity = None;
    let mut code = None;
    let mut message = None;
    loop {
        let field = r.u8()?;
        if field == 0 {
            break;
        }
        // Server messages are in the connection's client_encoding, which lokaj pins to UTF8.
        let value = String::from_utf8_lossy(r.cbytes()?).into_owned();
        match field {
            b'S' => localized = Some(value),
            b'V' => severity = Some(value),
            b'C' => code = Some(value),
            b'M' => message = Some(value),
            _ => {}
        }
    }
    r.finish()?;
    Ok(ErrorFields {
        severity: severity.or(localized).unwrap_or_default(),
        code: code.unwrap_or_default(),
        message: message.unwrap_or_default(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication<'a> {
    Ok,
    CleartextPassword,
    Md5Password,
    Sasl { mechanisms: Vec<&'a str> },
    SaslContinue(&'a [u8]),
    SaslFinal(&'a [u8]),
    Other(i32),
}

pub fn parse_authentication(body: &[u8]) -> Result<Authentication<'_>, ProtocolError> {
    let mut r = Reader::new(body, "Authentication");
    let auth = match r.i32()? {
        0 => Authentication::Ok,
        3 => Authentication::CleartextPassword,
        5 => Authentication::Md5Password,
        10 => {
            let mut mechanisms = Vec::new();
            loop {
                let mechanism = r.cstr()?;
                if mechanism.is_empty() {
                    break;
                }
                mechanisms.push(mechanism);
            }
            Authentication::Sasl { mechanisms }
        }
        11 => Authentication::SaslContinue(r.rest()),
        12 => Authentication::SaslFinal(r.rest()),
        other => {
            r.rest();
            Authentication::Other(other)
        }
    };
    r.finish()?;
    Ok(auth)
}

pub fn parse_backend_key_data(body: &[u8]) -> Result<(i32, Vec<u8>), ProtocolError> {
    let mut r = Reader::new(body, "BackendKeyData");
    let process_id = r.i32()?;
    let secret = r.rest();
    if secret.len() < 4 || secret.len() > MAX_CANCEL_KEY {
        return Err(ProtocolError::Malformed("BackendKeyData"));
    }
    Ok((process_id, secret.to_vec()))
}

// ---------------------------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------------------------

fn message(out: &mut BytesMut, tag: u8, body: impl FnOnce(&mut BytesMut)) {
    out.put_u8(tag);
    let len_at = out.len();
    out.put_i32(0);
    body(out);
    let len = (out.len() - len_at) as i32;
    out[len_at..len_at + 4].copy_from_slice(&len.to_be_bytes());
}

fn put_cstr(out: &mut BytesMut, s: &str) {
    out.put_slice(s.as_bytes());
    out.put_u8(0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Fatal,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Fatal => "FATAL",
        }
    }
}

pub fn error_response(out: &mut BytesMut, severity: Severity, code: &str, msg: &str) {
    message(out, tag::ERROR_RESPONSE, |out| {
        for (field, value) in [
            (b'S', severity.as_str()),
            (b'V', severity.as_str()),
            (b'C', code),
            (b'M', msg),
        ] {
            out.put_u8(field);
            put_cstr(out, value);
        }
        out.put_u8(0);
    });
}

pub fn authentication_ok(out: &mut BytesMut) {
    message(out, tag::AUTHENTICATION, |out| out.put_i32(0));
}

pub fn authentication_cleartext_password(out: &mut BytesMut) {
    message(out, tag::AUTHENTICATION, |out| out.put_i32(3));
}

pub fn parameter_status(out: &mut BytesMut, name: &str, value: &str) {
    message(out, tag::PARAMETER_STATUS, |out| {
        put_cstr(out, name);
        put_cstr(out, value);
    });
}

pub fn backend_key_data(out: &mut BytesMut, process_id: i32, secret: &[u8]) {
    message(out, tag::BACKEND_KEY_DATA, |out| {
        out.put_i32(process_id);
        out.put_slice(secret);
    });
}

pub fn ready_for_query(out: &mut BytesMut, status: TxStatus) {
    message(out, tag::READY_FOR_QUERY, |out| out.put_u8(status.byte()));
}

pub fn negotiate_protocol_version(out: &mut BytesMut, minor: u16, unrecognized: &[&str]) {
    message(out, tag::NEGOTIATE_PROTOCOL_VERSION, |out| {
        out.put_i32((3 << 16) | i32::from(minor));
        out.put_i32(unrecognized.len() as i32);
        for name in unrecognized {
            put_cstr(out, name);
        }
    });
}

pub fn startup_message(out: &mut BytesMut, params: &[(&str, &str)]) {
    let len_at = out.len();
    out.put_i32(0);
    out.put_i32(3 << 16);
    for (name, value) in params {
        put_cstr(out, name);
        put_cstr(out, value);
    }
    out.put_u8(0);
    let len = (out.len() - len_at) as i32;
    out[len_at..len_at + 4].copy_from_slice(&len.to_be_bytes());
}

pub fn sasl_initial_response(out: &mut BytesMut, mechanism: &str, data: &[u8]) {
    message(out, b'p', |out| {
        put_cstr(out, mechanism);
        out.put_i32(data.len() as i32);
        out.put_slice(data);
    });
}

pub fn sasl_response(out: &mut BytesMut, data: &[u8]) {
    message(out, b'p', |out| out.put_slice(data));
}

pub fn sync(out: &mut BytesMut) {
    message(out, b'S', |_| {});
}

pub fn terminate(out: &mut BytesMut) {
    message(out, b'X', |_| {});
}

pub fn ssl_request() -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&8i32.to_be_bytes());
    out[4..].copy_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
    out
}

pub fn cancel_request(process_id: i32, secret: &[u8]) -> BytesMut {
    let mut out = BytesMut::with_capacity(12 + secret.len());
    out.put_i32(12 + secret.len() as i32);
    out.put_i32(CANCEL_REQUEST_CODE);
    out.put_i32(process_id);
    out.put_slice(secret);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(packet: &BytesMut) -> &[u8] {
        &packet[4..]
    }

    #[test]
    fn startup_round_trip() {
        let mut out = BytesMut::new();
        startup_message(&mut out, &[("user", "u"), ("database", "d")]);
        let len = startup_packet_len([out[0], out[1], out[2], out[3]]).unwrap();
        assert_eq!(len, out.len());
        assert_eq!(
            parse_startup_packet(body(&out)).unwrap(),
            StartupPacket::Startup {
                minor: 0,
                params: vec![("user".into(), "u".into()), ("database".into(), "d".into())],
            }
        );
    }

    #[test]
    fn startup_requires_terminator_as_last_byte() {
        let mut out = BytesMut::new();
        startup_message(&mut out, &[("user", "u")]);
        out.put_u8(b'x');
        assert!(parse_startup_packet(body(&out)).is_err());
    }

    #[test]
    fn startup_rejects_other_major_versions() {
        let mut packet = BytesMut::new();
        packet.put_i32(2 << 16);
        packet.put_u8(0);
        assert_eq!(
            parse_startup_packet(&packet),
            Err(ProtocolError::UnsupportedVersion { major: 2, minor: 0 })
        );
    }

    #[test]
    fn cancel_request_round_trip() {
        let packet = cancel_request(42, &[1, 2, 3, 4]);
        assert_eq!(
            parse_startup_packet(&packet[4..]).unwrap(),
            StartupPacket::Cancel {
                process_id: 42,
                secret: vec![1, 2, 3, 4]
            }
        );
    }

    #[test]
    fn frame_waits_for_full_message_and_bounds_size() {
        let mut out = BytesMut::new();
        message(&mut out, b'Q', |out| put_cstr(out, "select 1"));
        assert_eq!(frame_at(&out[..out.len() - 1], 1024), Ok(None));
        assert_eq!(frame_at(&out, 1024), Ok(Some((b'Q', out.len()))));
        assert_eq!(frame_at(&out, 4), Err(ProtocolError::TooLarge(out.len())));
        assert!(frame_at(&[b'Q', 0, 0, 0, 3], 1024).is_err());
    }

    #[test]
    fn query_must_be_consumed_exactly() {
        assert_eq!(
            parse_frontend(b'Q', b"select 1\0").unwrap(),
            FrontendMessage::Query { sql: "select 1" }
        );
        assert!(parse_frontend(b'Q', b"select 1\0; set x = 1\0").is_err());
        assert!(parse_frontend(b'Q', b"select 1").is_err());
    }

    #[test]
    fn parse_message_checks_parameter_types() {
        let mut body = b"\0select $1\0".to_vec();
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(&23i32.to_be_bytes());
        assert_eq!(
            parse_frontend(b'P', &body).unwrap(),
            FrontendMessage::Parse {
                statement: "",
                sql: "select $1"
            }
        );
        body.push(0);
        assert!(parse_frontend(b'P', &body).is_err());
    }

    #[test]
    fn error_response_round_trip() {
        let mut out = BytesMut::new();
        error_response(&mut out, Severity::Fatal, "57P01", "bye");
        let fields = parse_error_response(&out[5..]).unwrap();
        assert_eq!(fields.code, "57P01");
        assert!(fields.is_fatal());
    }
}
