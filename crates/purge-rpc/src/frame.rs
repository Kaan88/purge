//! Newline-delimited JSON-RPC 2.0 framing (M3_DESIGN.md §6.1).
//!
//! - One JSON-RPC 2.0 object per line, UTF-8; `\n` ends a line. No batch arrays.
//! - Request ids are unsigned integers chosen by the client ([`RequestId`]). A notification has no id.
//! - A line over the reader's limit is an error ([`FrameError::Oversize`]): the server closes the
//!   transport, since it cannot tell where the next line starts without reading the rest.
//! - A line that is not UTF-8 or not JSON is answered with `-32700`; framing is not lost, because `\n`
//!   never occurs inside a UTF-8 sequence, so the server reads on.
//!
//! The codec works over [`BufRead`] and [`Write`]; it owns no handle and starts no thread.

use std::borrow::Cow;
use std::io::{self, BufRead, Write};

use schemars::JsonSchema;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::error::{ErrorObject, INVALID_REQUEST, PARSE_ERROR};

/// The `jsonrpc` member of every message.
pub const JSONRPC: &str = "2.0";

/// The id of a request: an unsigned integer the client chooses. Progress notifications name the request
/// they belong to by it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct RequestId(pub u64);

/// Why a transport cannot go on.
#[derive(Debug)]
pub enum FrameError {
    /// The underlying read or write failed.
    Io(io::Error),
    /// A line into the server is longer than the limit; the server closes the transport.
    Oversize {
        /// The limit in bytes, without the `\n`.
        limit: usize,
    },
    /// The stream ended inside a line.
    Truncated,
    /// A line to be written is longer than the output limit. Nothing was written.
    OutOversize {
        /// The line's length.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// A notification that the transport does not carry. Nothing was written.
    NotOnTransport(&'static str),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "transport: {e}"),
            FrameError::Oversize { limit } => write!(f, "a line is longer than {limit} bytes"),
            FrameError::Truncated => f.write_str("the stream ended inside a line"),
            FrameError::OutOversize { len, limit } => {
                write!(f, "an answer of {len} bytes is over the {limit}-byte limit")
            }
            FrameError::NotOnTransport(method) => {
                write!(f, "notification {method} is not sent on this transport")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Reads lines of at most `limit` bytes (the `\n` not counted). A line split over several reads is put
/// together. After an error the reader must not be used again.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    limit: usize,
    buf: Vec<u8>,
}

impl<R: BufRead> FrameReader<R> {
    /// A reader with a line limit.
    pub fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            limit,
            buf: Vec::new(),
        }
    }

    /// The next line without its `\n`; `None` at the end of the stream. The bytes are not checked: see
    /// [`parse_incoming`].
    pub fn read_line(&mut self) -> Result<Option<&[u8]>, FrameError> {
        self.buf.clear();
        loop {
            let available = match self.inner.fill_buf() {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(FrameError::Io(e)),
            };
            if available.is_empty() {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(FrameError::Truncated)
                };
            }
            let (take, end) = match available.iter().position(|&b| b == b'\n') {
                Some(at) => (at, true),
                None => (available.len(), false),
            };
            if self.buf.len() + take > self.limit {
                return Err(FrameError::Oversize { limit: self.limit });
            }
            self.buf.extend_from_slice(&available[..take]);
            self.inner.consume(take + usize::from(end));
            if end {
                return Ok(Some(&self.buf));
            }
        }
    }
}

/// Writes one message per line, at most `limit` bytes each (the `\n` not counted), and flushes after
/// every line.
#[derive(Debug)]
pub struct FrameWriter<W> {
    inner: W,
    limit: usize,
}

impl<W: Write> FrameWriter<W> {
    /// A writer with a line limit.
    pub fn new(inner: W, limit: usize) -> Self {
        Self { inner, limit }
    }

    /// Serialises `message` compactly and writes it as one line. Over the limit nothing is written.
    pub fn send<T: Serialize + ?Sized>(&mut self, message: &T) -> Result<(), FrameError> {
        // Compact serde_json output never holds a raw newline: one in a string is written `\n`.
        let mut line = serde_json::to_vec(message).map_err(io::Error::other)?;
        if line.len() > self.limit {
            return Err(FrameError::OutOversize {
                len: line.len(),
                limit: self.limit,
            });
        }
        line.push(b'\n');
        self.inner.write_all(&line)?;
        self.inner.flush()?;
        Ok(())
    }

    /// The wrapped writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

/// One message from the client, after the envelope checks.
#[derive(Debug, Clone)]
pub enum Incoming<'a> {
    /// A request: it gets exactly one response.
    Request {
        /// Its id.
        id: RequestId,
        /// The method name.
        method: Cow<'a, str>,
        /// The params as written; `None` when absent or `null`.
        params: Option<&'a RawValue>,
    },
    /// A notification: it never gets a response.
    Notification {
        /// The method name.
        method: Cow<'a, str>,
        /// The params as written; `None` when absent or `null`.
        params: Option<&'a RawValue>,
    },
}

/// A line the server answers with an error at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// The request id, when the envelope got far enough to have one; else the response has `id: null`.
    pub id: Option<RequestId>,
    /// The error.
    pub error: ErrorObject,
}

impl Rejected {
    /// The response to send.
    pub fn response(self) -> Response {
        Response {
            id: self.id,
            body: Err(self.error),
        }
    }
}

/// The `id` member, distinguishing absent (`None`) from present, `null` included.
#[derive(Default)]
struct RawId<'a>(Option<&'a RawValue>);

impl<'de: 'a, 'a> Deserialize<'de> for RawId<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <&'a RawValue>::deserialize(deserializer).map(|raw| RawId(Some(raw)))
    }
}

/// The envelope of a client message. Unknown members are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    #[serde(borrow)]
    jsonrpc: Cow<'a, str>,
    #[serde(default, borrow)]
    id: RawId<'a>,
    #[serde(borrow)]
    method: Cow<'a, str>,
    #[serde(default, borrow)]
    params: Option<&'a RawValue>,
}

fn reject(id: Option<RequestId>, code: i32, message: impl Into<String>) -> Rejected {
    Rejected {
        id,
        error: ErrorObject::protocol(code, message),
    }
}

/// Checks one line from the client: UTF-8, JSON, one object (no batch array), `jsonrpc: "2.0"`, an id
/// that is an unsigned integer or absent, a method name, no other member. Params, when present and not
/// `null`, are passed on as written; the method decides their form.
pub fn parse_incoming(line: &[u8]) -> Result<Incoming<'_>, Rejected> {
    let text = std::str::from_utf8(line)
        .map_err(|_| reject(None, PARSE_ERROR, "the line is not UTF-8"))?;
    match text
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .as_bytes()
        .first()
    {
        Some(b'{') => {}
        Some(b'[') => {
            return Err(reject(
                None,
                INVALID_REQUEST,
                "batch arrays are not taken: one request per line",
            ));
        }
        _ => {
            return Err(match serde_json::from_str::<serde::de::IgnoredAny>(text) {
                Ok(_) => reject(None, INVALID_REQUEST, "a message is a JSON object"),
                Err(_) => reject(None, PARSE_ERROR, "the line is not JSON"),
            });
        }
    }
    let envelope: Envelope<'_> = serde_json::from_str(text).map_err(|e| {
        if e.is_data() {
            reject(None, INVALID_REQUEST, format!("bad envelope: {e}"))
        } else {
            reject(None, PARSE_ERROR, format!("the line is not JSON: {e}"))
        }
    })?;
    let id = match envelope.id.0 {
        None => None,
        Some(raw) => Some(RequestId(serde_json::from_str::<u64>(raw.get()).map_err(
            |_| reject(None, INVALID_REQUEST, "a request id is an unsigned integer"),
        )?)),
    };
    if envelope.jsonrpc != JSONRPC {
        return Err(reject(id, INVALID_REQUEST, "jsonrpc must be \"2.0\""));
    }
    let method = envelope.method;
    let params = envelope.params;
    Ok(match id {
        Some(id) => Incoming::Request { id, method, params },
        None => Incoming::Notification { method, params },
    })
}

/// A response: exactly one per request.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    /// The request's id; `None` (written `null`) when the request's id could not be read.
    pub id: Option<RequestId>,
    /// The result, or the error.
    pub body: Result<Value, ErrorObject>,
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("jsonrpc", JSONRPC)?;
        map.serialize_entry("id", &self.id)?;
        match &self.body {
            Ok(result) => map.serialize_entry("result", result)?,
            Err(error) => map.serialize_entry("error", error)?,
        }
        map.end()
    }
}

/// A notification from the server (or the client's `$/cancel`), ready to write.
#[derive(Debug, Clone, Copy)]
pub struct NotificationLine<'a, P: ?Sized> {
    /// The method name.
    pub method: &'a str,
    /// The params.
    pub params: &'a P,
}

impl<P: Serialize + ?Sized> Serialize for NotificationLine<'_, P> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("jsonrpc", JSONRPC)?;
        map.serialize_entry("method", self.method)?;
        map.serialize_entry("params", self.params)?;
        map.end()
    }
}

/// A request as a client writes it (the rig, tests).
#[derive(Debug, Clone, Copy)]
pub struct RequestLine<'a, P: ?Sized> {
    /// Its id.
    pub id: RequestId,
    /// The method name.
    pub method: &'a str,
    /// The params; `None` writes none.
    pub params: Option<&'a P>,
}

impl<P: Serialize + ?Sized> Serialize for RequestLine<'_, P> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("jsonrpc", JSONRPC)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("method", self.method)?;
        if let Some(params) = self.params {
            map.serialize_entry("params", params)?;
        }
        map.end()
    }
}

/// One message from the server, as a client reads it.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerMessage {
    /// A response.
    Response(Response),
    /// A notification.
    Notification {
        /// The method name.
        method: String,
        /// The params (`null` when absent).
        params: Value,
    },
}

/// Reads one line a server wrote. Errors when it is not a JSON-RPC 2.0 response or notification.
pub fn parse_server_line(line: &[u8]) -> Result<ServerMessage, String> {
    let value: Value = serde_json::from_slice(line).map_err(|e| e.to_string())?;
    let Value::Object(mut map) = value else {
        return Err("a message is a JSON object".into());
    };
    if map.remove("jsonrpc") != Some(Value::String(JSONRPC.into())) {
        return Err("jsonrpc must be \"2.0\"".into());
    }
    if let Some(method) = map.remove("method") {
        let Value::String(method) = method else {
            return Err("method is a string".into());
        };
        let params = map.remove("params").unwrap_or(Value::Null);
        if !map.is_empty() {
            return Err("unknown members in a notification".into());
        }
        return Ok(ServerMessage::Notification { method, params });
    }
    let id = match map.remove("id") {
        None => return Err("a response has an id".into()),
        Some(Value::Null) => None,
        Some(id) => Some(serde_json::from_value::<RequestId>(id).map_err(|e| e.to_string())?),
    };
    let body = match (map.remove("result"), map.remove("error")) {
        (Some(result), None) => Ok(result),
        (None, Some(error)) => {
            Err(serde_json::from_value::<ErrorObject>(error).map_err(|e| e.to_string())?)
        }
        _ => return Err("a response has exactly one of result and error".into()),
    };
    if !map.is_empty() {
        return Err("unknown members in a response".into());
    }
    Ok(ServerMessage::Response(Response { id, body }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::METHOD_NOT_FOUND;

    /// A reader that returns at most `step` bytes per read, so lines arrive split.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl io::Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    fn lines(data: &[u8], step: usize, limit: usize) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut reader = FrameReader::new(
            io::BufReader::with_capacity(step.max(1), Trickle { data, step }),
            limit,
        );
        let mut out = Vec::new();
        while let Some(line) = reader.read_line()? {
            out.push(line.to_vec());
        }
        Ok(out)
    }

    #[test]
    fn split_lines_are_put_together() {
        let data = b"{\"a\":1}\n{\"b\":22}\n\n{\"c\":333}\n";
        for step in [1, 2, 3, 7, 64] {
            let got = lines(data, step, 64).unwrap();
            assert_eq!(
                got,
                vec![
                    b"{\"a\":1}".to_vec(),
                    b"{\"b\":22}".to_vec(),
                    Vec::new(),
                    b"{\"c\":333}".to_vec()
                ],
                "step {step}"
            );
        }
    }

    #[test]
    fn a_line_at_the_limit_passes_and_one_byte_more_closes() {
        let mut data = vec![b'x'; 16];
        data.push(b'\n');
        assert_eq!(lines(&data, 3, 16).unwrap().len(), 1);
        let mut data = vec![b'x'; 17];
        data.push(b'\n');
        for step in [1, 5, 64] {
            assert!(matches!(
                lines(&data, step, 16),
                Err(FrameError::Oversize { limit: 16 })
            ));
        }
        // Over the limit without any newline at all: refused before the stream ends.
        let data = vec![b'x'; 1000];
        assert!(matches!(
            lines(&data, 7, 16),
            Err(FrameError::Oversize { .. })
        ));
    }

    #[test]
    fn a_stream_ending_inside_a_line_is_truncated() {
        assert!(matches!(
            lines(b"{\"a\":1}\n{\"b\"", 4, 64),
            Err(FrameError::Truncated)
        ));
        assert!(lines(b"", 4, 64).unwrap().is_empty());
    }

    #[test]
    fn invalid_utf8_is_a_parse_error_and_the_next_line_still_reads() {
        let data = b"{\"jsonrpc\":\"2.0\",\"method\":\"\xff\xfe\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"engine.hello\"}\n";
        let got = lines(data, 5, 128).unwrap();
        assert_eq!(got.len(), 2);
        let rejected = parse_incoming(&got[0]).unwrap_err();
        assert_eq!(rejected.id, None);
        assert_eq!(rejected.error.code, PARSE_ERROR);
        assert!(matches!(
            parse_incoming(&got[1]).unwrap(),
            Incoming::Request {
                id: RequestId(1),
                ..
            }
        ));
    }

    #[test]
    fn batch_arrays_are_refused() {
        for line in [
            &br#"[{"jsonrpc":"2.0","id":1,"method":"engine.hello"}]"#[..],
            b"  []",
            br#"["2.0", 1, "engine.hello"]"#,
        ] {
            let rejected = parse_incoming(line).unwrap_err();
            assert_eq!(rejected.error.code, INVALID_REQUEST, "{line:?}");
            assert_eq!(rejected.id, None);
        }
    }

    #[test]
    fn envelope_checks() {
        let code = |line: &str| parse_incoming(line.as_bytes()).unwrap_err().error.code;
        assert_eq!(code(""), PARSE_ERROR);
        assert_eq!(code("{"), PARSE_ERROR);
        assert_eq!(code("nul"), PARSE_ERROR);
        assert_eq!(code("17"), INVALID_REQUEST);
        assert_eq!(code(r#""x""#), INVALID_REQUEST);
        assert_eq!(code(r#"{"id":1,"method":"engine.hello"}"#), INVALID_REQUEST);
        assert_eq!(
            code(r#"{"jsonrpc":"1.0","id":1,"method":"engine.hello"}"#),
            INVALID_REQUEST
        );
        assert_eq!(code(r#"{"jsonrpc":"2.0","id":1}"#), INVALID_REQUEST);
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","id":1,"method":"engine.hello","path":"C:\\x"}"#),
            INVALID_REQUEST
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"engine.hello"}"#),
            INVALID_REQUEST
        );
        for id in [
            "-1",
            "1.5",
            "1e3",
            "\"1\"",
            "null",
            "{}",
            "18446744073709551616",
        ] {
            let line = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"engine.hello"}}"#);
            let rejected = parse_incoming(line.as_bytes()).unwrap_err();
            assert_eq!(rejected.error.code, INVALID_REQUEST, "id {id}");
            assert_eq!(rejected.id, None);
        }
        // The id is known once read, so a later envelope error answers with it.
        let rejected =
            parse_incoming(br#"{"jsonrpc":"2.1","id":7,"method":"engine.hello"}"#).unwrap_err();
        assert_eq!(rejected.id, Some(RequestId(7)));
    }

    #[test]
    fn requests_and_notifications() {
        let max = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"engine.hello"}}"#,
            u64::MAX
        );
        assert!(matches!(
            parse_incoming(max.as_bytes()).unwrap(),
            Incoming::Request {
                id: RequestId(u64::MAX),
                params: None,
                ..
            }
        ));
        let Incoming::Request { method, params, .. } = parse_incoming(
            br#"{"jsonrpc":"2.0","id":3,"method":"engine\u002ehello","params":null}"#,
        )
        .unwrap() else {
            panic!("a request")
        };
        assert_eq!(method, "engine.hello");
        assert!(params.is_none());
        let Incoming::Notification { method, params } =
            parse_incoming(br#"{"jsonrpc":"2.0","method":"$/cancel","params":{"request":3}}"#)
                .unwrap()
        else {
            panic!("a notification")
        };
        assert_eq!(method, "$/cancel");
        assert_eq!(params.unwrap().get(), r#"{"request":3}"#);
    }

    #[test]
    fn writer_limits_and_lines() {
        let mut writer = FrameWriter::new(Vec::new(), 40);
        writer.send(&serde_json::json!({"a": "x\ny"})).unwrap();
        assert_eq!(writer.get_mut().as_slice(), b"{\"a\":\"x\\ny\"}\n");
        let long = "z".repeat(64);
        assert!(matches!(
            writer.send(&serde_json::json!({ "a": long })),
            Err(FrameError::OutOversize { limit: 40, .. })
        ));
        assert_eq!(writer.get_mut().len(), 13, "nothing written over the limit");
    }

    #[test]
    fn server_lines_read_back() {
        let ok = Response {
            id: Some(RequestId(4)),
            body: Ok(serde_json::json!({"count": 2})),
        };
        let err = Response {
            id: None,
            body: Err(ErrorObject::method_not_found()),
        };
        for response in [ok, err] {
            let line = serde_json::to_vec(&response).unwrap();
            assert_eq!(
                parse_server_line(&line).unwrap(),
                ServerMessage::Response(response)
            );
        }
        let note = NotificationLine {
            method: "size.ready",
            params: &serde_json::json!({"request": 4}),
        };
        let line = serde_json::to_vec(&note).unwrap();
        assert_eq!(
            parse_server_line(&line).unwrap(),
            ServerMessage::Notification {
                method: "size.ready".into(),
                params: serde_json::json!({"request": 4})
            }
        );
        let request = RequestLine::<Value> {
            id: RequestId(9),
            method: "engine.hello",
            params: None,
        };
        let line = serde_json::to_vec(&request).unwrap();
        assert!(matches!(
            parse_incoming(&line).unwrap(),
            Incoming::Request {
                id: RequestId(9),
                ..
            }
        ));
        assert_eq!(
            Rejected {
                id: None,
                error: ErrorObject::method_not_found()
            }
            .response()
            .body
            .unwrap_err()
            .code,
            METHOD_NOT_FOUND
        );
    }
}
