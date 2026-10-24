//! Transaction-pooling relay: the state of one assignment of a server connection to a client,
//! and the inspector for the server's message stream. Both are free of I/O so their invariants
//! can be tested directly.
//!
//! A connection is assigned on the client's first message after `ReadyForQuery 'I'` and may be
//! released only once the server answered every `Query`/`Sync` sent to it, reported `Idle`, and
//! no extended-protocol batch is open.

use bytes::BytesMut;

use crate::protocol::{self, FrontendMessage, ProtocolError, Target, TxStatus, tag};
use crate::server::Params;
use crate::sql_guard;

/// A client message lokaj refuses; the client is sent a FATAL error and disconnected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub code: &'static str,
    pub message: String,
}

fn rejected(code: &'static str, message: impl Into<String>) -> Rejected {
    Rejected {
        code,
        message: format!("lokaj: {}", message.into()),
    }
}

const FEATURE_NOT_SUPPORTED: &str = "0A000";
const PROTOCOL_VIOLATION: &str = "08P01";
const INVALID_SQL_STATEMENT_NAME: &str = "26000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendAction {
    Forward,
    Terminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// `Query` and `Sync` messages forwarded and not yet answered by `ReadyForQuery`.
    pending: u32,
    /// Extended-protocol messages were forwarded since the last `Sync`.
    open_batch: bool,
    status: TxStatus,
    /// The unnamed statement and portal were created in the current batch. Ones left on the
    /// connection by an earlier client must never be used, and after a `Sync` lokaj cannot know
    /// whether the server accepted the creating message, so they count only until then.
    unnamed_statement: bool,
    unnamed_portal: bool,
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}

impl Relay {
    pub fn new() -> Self {
        Self {
            pending: 0,
            open_batch: false,
            status: TxStatus::Idle,
            unnamed_statement: false,
            unnamed_portal: false,
        }
    }

    /// Validates a client message and records its effect. On `Ok(Forward)` the caller sends the
    /// message to the server unchanged.
    pub fn on_frontend(&mut self, msg: &FrontendMessage<'_>) -> Result<FrontendAction, Rejected> {
        match *msg {
            FrontendMessage::Query { sql } => {
                if self.open_batch {
                    return Err(rejected(
                        PROTOCOL_VIOLATION,
                        "simple query inside an unfinished extended-protocol batch",
                    ));
                }
                guard(sql)?;
                self.pending += 1;
                self.unnamed_statement = false;
                self.unnamed_portal = false;
            }
            FrontendMessage::Parse { statement, sql } => {
                if !statement.is_empty() {
                    return Err(rejected(
                        FEATURE_NOT_SUPPORTED,
                        "named prepared statements are not supported",
                    ));
                }
                guard(sql)?;
                self.open_batch = true;
                self.unnamed_statement = true;
            }
            FrontendMessage::Bind { portal, statement } => {
                if !portal.is_empty() || !statement.is_empty() {
                    return Err(rejected(
                        FEATURE_NOT_SUPPORTED,
                        "named portals and prepared statements are not supported",
                    ));
                }
                if !self.unnamed_statement {
                    return Err(rejected(
                        INVALID_SQL_STATEMENT_NAME,
                        "Bind without a preceding Parse in this transaction",
                    ));
                }
                self.open_batch = true;
                self.unnamed_portal = true;
            }
            FrontendMessage::Describe { target, name }
            | FrontendMessage::Close { target, name } => {
                if !name.is_empty() {
                    return Err(rejected(
                        FEATURE_NOT_SUPPORTED,
                        "named portals and prepared statements are not supported",
                    ));
                }
                let created = match target {
                    Target::Statement => self.unnamed_statement,
                    Target::Portal => self.unnamed_portal,
                };
                if matches!(msg, FrontendMessage::Describe { .. }) && !created {
                    return Err(rejected(
                        INVALID_SQL_STATEMENT_NAME,
                        "Describe of an object not created in this transaction",
                    ));
                }
                self.open_batch = true;
            }
            FrontendMessage::Execute { portal } => {
                if !portal.is_empty() {
                    return Err(rejected(
                        FEATURE_NOT_SUPPORTED,
                        "named portals are not supported",
                    ));
                }
                if !self.unnamed_portal {
                    return Err(rejected(
                        INVALID_SQL_STATEMENT_NAME,
                        "Execute without a preceding Bind in this transaction",
                    ));
                }
                self.open_batch = true;
            }
            FrontendMessage::Sync => {
                self.pending += 1;
                self.open_batch = false;
                self.unnamed_statement = false;
                self.unnamed_portal = false;
            }
            FrontendMessage::Flush => {}
            FrontendMessage::Terminate => return Ok(FrontendAction::Terminate),
            FrontendMessage::FunctionCall => {
                return Err(rejected(
                    FEATURE_NOT_SUPPORTED,
                    "the function call protocol is not supported",
                ));
            }
            FrontendMessage::CopyData | FrontendMessage::CopyDone | FrontendMessage::CopyFail => {
                return Err(rejected(FEATURE_NOT_SUPPORTED, "COPY is not supported"));
            }
            FrontendMessage::Password { .. } | FrontendMessage::Unknown { .. } => {
                return Err(rejected(PROTOCOL_VIOLATION, "unexpected message"));
            }
        }
        Ok(FrontendAction::Forward)
    }

    /// Records a `ReadyForQuery`; returns whether the connection may now be released.
    pub fn on_ready_for_query(&mut self, status: TxStatus) -> Result<bool, ServerViolation> {
        if self.pending == 0 {
            return Err(ServerViolation::Protocol(
                "unsolicited ReadyForQuery".into(),
            ));
        }
        self.pending -= 1;
        self.status = status;
        Ok(self.can_release())
    }

    pub fn can_release(&self) -> bool {
        self.status == TxStatus::Idle && self.pending == 0 && !self.open_batch
    }

    /// Whether the server answered everything it was sent and now waits for the client.
    pub fn awaits_client(&self) -> bool {
        self.pending == 0
    }

    /// Whether the server may be executing something for this client.
    pub fn in_flight(&self) -> bool {
        self.pending > 0 || self.open_batch
    }
}

fn guard(sql: &str) -> Result<(), Rejected> {
    sql_guard::check(sql).map_err(|r| {
        rejected(
            FEATURE_NOT_SUPPORTED,
            format!(
                "{} is not supported in transaction pooling mode",
                r.statement
            ),
        )
    })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerViolation {
    #[error("the server started COPY")]
    Copy,
    #[error("server protocol violation: {0}")]
    Protocol(String),
}

impl From<ProtocolError> for ServerViolation {
    fn from(error: ProtocolError) -> Self {
        ServerViolation::Protocol(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// The connection may be released; nothing after the final `ReadyForQuery` was consumed.
    Release,
    /// The server sent a FATAL error and is closing the connection.
    Fatal,
}

/// Largest server message lokaj parses during the relay; all others are streamed through.
const MAX_INSPECTED: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Header,
    Body { tag: u8, len: usize },
    PassThrough { remaining: usize },
}

/// Splits the server's byte stream into messages without buffering whole data rows: only
/// `ReadyForQuery`, `ParameterStatus` and `ErrorResponse` are parsed.
#[derive(Debug)]
pub struct BackendStream {
    state: StreamState,
}

impl Default for BackendStream {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendStream {
    pub fn new() -> Self {
        Self {
            state: StreamState::Header,
        }
    }

    /// Whether the stream ended on a message boundary.
    pub fn at_boundary(&self) -> bool {
        self.state == StreamState::Header
    }

    /// Moves server bytes from `input` to `out`, updating `relay` and `params`. Stops right after
    /// the `ReadyForQuery` that makes the connection releasable.
    pub fn feed(
        &mut self,
        input: &mut BytesMut,
        out: &mut BytesMut,
        relay: &mut Relay,
        params: &mut Params,
    ) -> Result<Flow, ServerViolation> {
        let mut flow = Flow::Continue;
        loop {
            match self.state {
                StreamState::Header => {
                    let Some((msg_tag, len)) = protocol::header_at(input)? else {
                        return Ok(flow);
                    };
                    match msg_tag {
                        tag::READY_FOR_QUERY | tag::PARAMETER_STATUS | tag::ERROR_RESPONSE => {
                            if len > MAX_INSPECTED {
                                return Err(ServerViolation::Protocol(format!(
                                    "{len} byte control message"
                                )));
                            }
                            self.state = StreamState::Body { tag: msg_tag, len };
                        }
                        tag::COPY_IN_RESPONSE
                        | tag::COPY_OUT_RESPONSE
                        | tag::COPY_BOTH_RESPONSE
                        | tag::COPY_DATA
                        | tag::COPY_DONE => return Err(ServerViolation::Copy),
                        tag::DATA_ROW
                        | tag::ROW_DESCRIPTION
                        | tag::COMMAND_COMPLETE
                        | tag::PARSE_COMPLETE
                        | tag::BIND_COMPLETE
                        | tag::CLOSE_COMPLETE
                        | tag::EMPTY_QUERY_RESPONSE
                        | tag::NO_DATA
                        | tag::PORTAL_SUSPENDED
                        | tag::PARAMETER_DESCRIPTION
                        | tag::NOTICE_RESPONSE
                        | tag::NOTIFICATION_RESPONSE => {
                            out.extend_from_slice(&input.split_to(5));
                            self.state = StreamState::PassThrough { remaining: len };
                        }
                        other => {
                            return Err(ServerViolation::Protocol(format!(
                                "unexpected message {:?}",
                                other as char
                            )));
                        }
                    }
                }
                StreamState::Body { tag: msg_tag, len } => {
                    if input.len() < 5 + len {
                        return Ok(flow);
                    }
                    let frame = input.split_to(5 + len);
                    let body = &frame[5..];
                    self.state = StreamState::Header;
                    match msg_tag {
                        tag::READY_FOR_QUERY => {
                            let status = protocol::parse_ready_for_query(body)?;
                            out.extend_from_slice(&frame);
                            if relay.on_ready_for_query(status)? {
                                return Ok(Flow::Release);
                            }
                        }
                        tag::PARAMETER_STATUS => {
                            let (name, value) = protocol::parse_parameter_status(body)?;
                            params.set(name, value);
                            // Each client keeps the application_name it sent at startup.
                            if name != "application_name" {
                                out.extend_from_slice(&frame);
                            }
                        }
                        _ => {
                            if protocol::parse_error_response(body)?.is_fatal() {
                                flow = Flow::Fatal;
                            }
                            out.extend_from_slice(&frame);
                        }
                    }
                }
                StreamState::PassThrough { remaining } => {
                    let n = remaining.min(input.len());
                    if n == 0 && remaining > 0 {
                        return Ok(flow);
                    }
                    out.extend_from_slice(&input.split_to(n));
                    self.state = match remaining - n {
                        0 => StreamState::Header,
                        remaining => StreamState::PassThrough { remaining },
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn rfq(status: u8) -> Vec<u8> {
        msg(b'Z', &[status])
    }

    #[test]
    fn simple_query_releases_on_idle() {
        let mut relay = Relay::new();
        assert_eq!(
            relay.on_frontend(&FrontendMessage::Query { sql: "select 1" }),
            Ok(FrontendAction::Forward)
        );
        assert!(!relay.can_release());
        assert_eq!(relay.on_ready_for_query(TxStatus::Idle), Ok(true));
    }

    #[test]
    fn transaction_keeps_the_connection() {
        let mut relay = Relay::new();
        relay
            .on_frontend(&FrontendMessage::Query { sql: "begin" })
            .unwrap();
        assert_eq!(relay.on_ready_for_query(TxStatus::InTransaction), Ok(false));
        relay
            .on_frontend(&FrontendMessage::Query { sql: "select 1" })
            .unwrap();
        assert_eq!(relay.on_ready_for_query(TxStatus::Failed), Ok(false));
        relay
            .on_frontend(&FrontendMessage::Query { sql: "rollback" })
            .unwrap();
        assert_eq!(relay.on_ready_for_query(TxStatus::Idle), Ok(true));
    }

    #[test]
    fn pipelined_queries_release_after_the_last_answer() {
        let mut relay = Relay::new();
        relay
            .on_frontend(&FrontendMessage::Query { sql: "select 1" })
            .unwrap();
        relay
            .on_frontend(&FrontendMessage::Query { sql: "select 2" })
            .unwrap();
        assert_eq!(relay.on_ready_for_query(TxStatus::Idle), Ok(false));
        assert_eq!(relay.on_ready_for_query(TxStatus::Idle), Ok(true));
        assert!(relay.on_ready_for_query(TxStatus::Idle).is_err());
    }

    #[test]
    fn extended_protocol_with_unnamed_objects() {
        let mut relay = Relay::new();
        for m in [
            FrontendMessage::Parse {
                statement: "",
                sql: "select $1",
            },
            FrontendMessage::Bind {
                portal: "",
                statement: "",
            },
            FrontendMessage::Describe {
                target: Target::Portal,
                name: "",
            },
            FrontendMessage::Execute { portal: "" },
        ] {
            relay.on_frontend(&m).unwrap();
            assert!(!relay.can_release());
        }
        relay.on_frontend(&FrontendMessage::Sync).unwrap();
        assert_eq!(relay.on_ready_for_query(TxStatus::Idle), Ok(true));
    }

    #[test]
    fn objects_from_an_earlier_assignment_are_off_limits() {
        let mut relay = Relay::new();
        assert!(
            relay
                .on_frontend(&FrontendMessage::Bind {
                    portal: "",
                    statement: ""
                })
                .is_err()
        );
        assert!(
            relay
                .on_frontend(&FrontendMessage::Execute { portal: "" })
                .is_err()
        );
        assert!(
            relay
                .on_frontend(&FrontendMessage::Describe {
                    target: Target::Statement,
                    name: ""
                })
                .is_err()
        );
    }

    #[test]
    fn objects_from_an_earlier_batch_are_off_limits() {
        // The Parse may fail on the server, leaving the previous client's statement in place.
        let mut relay = Relay::new();
        for m in [
            FrontendMessage::Parse {
                statement: "",
                sql: "select $1",
            },
            FrontendMessage::Bind {
                portal: "",
                statement: "",
            },
            FrontendMessage::Sync,
        ] {
            relay.on_frontend(&m).unwrap();
        }
        let bind = relay.on_frontend(&FrontendMessage::Bind {
            portal: "",
            statement: "",
        });
        assert_eq!(bind.unwrap_err().code, INVALID_SQL_STATEMENT_NAME);
        let execute = relay.on_frontend(&FrontendMessage::Execute { portal: "" });
        assert_eq!(execute.unwrap_err().code, INVALID_SQL_STATEMENT_NAME);
    }

    #[test]
    fn rejects_named_objects_copy_and_session_state() {
        let mut relay = Relay::new();
        for m in [
            FrontendMessage::Parse {
                statement: "s1",
                sql: "select 1",
            },
            FrontendMessage::Bind {
                portal: "p",
                statement: "",
            },
            FrontendMessage::Close {
                target: Target::Statement,
                name: "s1",
            },
            FrontendMessage::FunctionCall,
            FrontendMessage::CopyData,
            FrontendMessage::Query {
                sql: "set search_path = x",
            },
            FrontendMessage::Parse {
                statement: "",
                sql: "discard all",
            },
        ] {
            assert!(relay.on_frontend(&m).is_err(), "{m:?}");
        }
    }

    /// Feeds `wire` in chunks of `size` through a persistent input buffer, as the session does.
    fn feed_all(wire: &[u8], size: usize, relay: &mut Relay) -> (Vec<u8>, Vec<Flow>, Params) {
        let mut stream = BackendStream::new();
        let mut params = Params::default();
        let mut input = BytesMut::new();
        let mut out = BytesMut::new();
        let mut flows = Vec::new();
        for chunk in wire.chunks(size) {
            input.extend_from_slice(chunk);
            let flow = stream
                .feed(&mut input, &mut out, relay, &mut params)
                .unwrap();
            if flow != Flow::Continue {
                flows.push(flow);
            }
        }
        assert!(input.is_empty());
        assert!(stream.at_boundary());
        (out.to_vec(), flows, params)
    }

    #[test]
    fn stream_forwards_everything_but_application_name() {
        for size in [1, 3, 7, 1000] {
            let mut relay = Relay::new();
            relay
                .on_frontend(&FrontendMessage::Query { sql: "select" })
                .unwrap();
            let mut wire = msg(b'T', &[1u8; 30]);
            wire.extend(msg(b'D', &[7u8; 100]));
            wire.extend(msg(b'S', b"application_name\0x\0"));
            wire.extend(msg(b'S', b"TimeZone\0UTC\0"));
            wire.extend(msg(b'C', b"SELECT 1\0"));
            let tail = rfq(b'I');
            wire.extend(&tail);
            let (out, flows, params) = feed_all(&wire, size, &mut relay);
            let mut expected = msg(b'T', &[1u8; 30]);
            expected.extend(msg(b'D', &[7u8; 100]));
            expected.extend(msg(b'S', b"TimeZone\0UTC\0"));
            expected.extend(msg(b'C', b"SELECT 1\0"));
            expected.extend(&tail);
            assert_eq!(out, expected);
            assert_eq!(flows, vec![Flow::Release]);
            assert!(params.changed);
            assert_eq!(
                params.values.get("TimeZone").map(String::as_str),
                Some("UTC")
            );
        }
    }

    #[test]
    fn stream_rejects_copy_and_reports_fatal_errors() {
        let mut relay = Relay::new();
        relay
            .on_frontend(&FrontendMessage::Query { sql: "select" })
            .unwrap();
        let mut stream = BackendStream::new();
        let mut input = BytesMut::from(&msg(b'H', &[0, 0, 0])[..]);
        let result = stream.feed(
            &mut input,
            &mut BytesMut::new(),
            &mut relay,
            &mut Params::default(),
        );
        assert_eq!(result, Err(ServerViolation::Copy));

        let mut error = BytesMut::new();
        protocol::error_response(
            &mut error,
            protocol::Severity::Fatal,
            "57P01",
            "terminating",
        );
        let (out, flows, _) = feed_all(&error, 4, &mut relay);
        assert_eq!(out, error.to_vec());
        assert_eq!(flows, vec![Flow::Fatal]);
    }

    /// A model of the server: executes forwarded messages in order and answers each `Query` and
    /// `Sync` with `ReadyForQuery` carrying its transaction status.
    #[derive(Debug, Default)]
    struct Server {
        status: Option<TxStatus>,
        skipping: bool,
        queue: std::collections::VecDeque<Client>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Client {
        Begin,
        Commit,
        Select,
        Fail,
        Parse,
        Bind,
        Execute,
        ExecuteFail,
        Sync,
        Flush,
    }

    impl Server {
        fn status(&self) -> TxStatus {
            self.status.unwrap_or(TxStatus::Idle)
        }

        fn fail(&mut self) {
            if self.status() == TxStatus::InTransaction {
                self.status = Some(TxStatus::Failed);
            }
        }

        /// Processes queued messages up to and including the next one that is answered.
        fn answer(&mut self) -> Option<TxStatus> {
            while let Some(m) = self.queue.pop_front() {
                match m {
                    Client::Begin | Client::Commit | Client::Select | Client::Fail => {
                        match (m, self.status()) {
                            (_, TxStatus::Failed) if m != Client::Commit => {}
                            (Client::Begin, _) => self.status = Some(TxStatus::InTransaction),
                            (Client::Commit, _) => self.status = Some(TxStatus::Idle),
                            (Client::Fail, _) => self.fail(),
                            _ => {}
                        }
                        return Some(self.status());
                    }
                    Client::Sync => {
                        self.skipping = false;
                        return Some(self.status());
                    }
                    Client::ExecuteFail if !self.skipping => {
                        self.fail();
                        self.skipping = true;
                    }
                    _ => {}
                }
            }
            None
        }

        fn answers_pending(&self) -> bool {
            self.queue.iter().any(|m| {
                matches!(
                    m,
                    Client::Begin | Client::Commit | Client::Select | Client::Fail | Client::Sync
                )
            })
        }
    }

    fn frontend(m: Client) -> FrontendMessage<'static> {
        match m {
            Client::Begin => FrontendMessage::Query { sql: "begin" },
            Client::Commit => FrontendMessage::Query { sql: "commit" },
            Client::Select => FrontendMessage::Query { sql: "select 1" },
            Client::Fail => FrontendMessage::Query { sql: "select 1/0" },
            Client::Parse => FrontendMessage::Parse {
                statement: "",
                sql: "select $1",
            },
            Client::Bind => FrontendMessage::Bind {
                portal: "",
                statement: "",
            },
            Client::Execute | Client::ExecuteFail => FrontendMessage::Execute { portal: "" },
            Client::Sync => FrontendMessage::Sync,
            Client::Flush => FrontendMessage::Flush,
        }
    }

    fn client_message() -> impl Strategy<Value = Client> {
        prop_oneof![
            Just(Client::Begin),
            Just(Client::Commit),
            Just(Client::Select),
            Just(Client::Fail),
            Just(Client::Parse),
            Just(Client::Bind),
            Just(Client::Execute),
            Just(Client::ExecuteFail),
            Just(Client::Sync),
            Just(Client::Flush),
        ]
    }

    proptest! {
        /// Whatever the client sends and however answers interleave, the relay releases the
        /// connection exactly when the server is idle with nothing left to answer and no batch is
        /// open: never while a transaction or a response is outstanding.
        #[test]
        fn releases_only_idle_connections(
            steps in proptest::collection::vec((client_message(), any::<bool>()), 1..80),
        ) {
            let mut server = Server::default();
            let mut relay = Relay::new();
            let mut batch_open = false;
            for (m, deliver) in steps {
                if deliver && let Some(status) = server.answer() {
                    let release = relay.on_ready_for_query(status).unwrap();
                    let model = status == TxStatus::Idle && !server.answers_pending() && !batch_open;
                    prop_assert_eq!(release, model);
                    if release {
                        relay = Relay::new();
                    }
                    continue;
                }
                match relay.on_frontend(&frontend(m)) {
                    Ok(FrontendAction::Forward) => {
                        server.queue.push_back(m);
                        batch_open = match m {
                            Client::Parse | Client::Bind | Client::Execute | Client::ExecuteFail => true,
                            Client::Sync => false,
                            _ => batch_open,
                        };
                    }
                    Ok(FrontendAction::Terminate) => unreachable!(),
                    // A rejected message ends the client's session.
                    Err(_) => break,
                }
                prop_assert!(!relay.can_release() || (!server.answers_pending() && server.status() == TxStatus::Idle));
                prop_assert_eq!(relay.in_flight(), server.answers_pending() || batch_open);
            }
        }
    }
}
