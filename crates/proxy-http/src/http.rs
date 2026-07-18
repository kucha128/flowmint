//! Minimal HTTP/1.1 wire parsing for the capture proxy.
//!
//! Deliberately small and dependency-free: enough to forward-proxy plain HTTP,
//! read Content-Length / chunked bodies, and normalize responses for relay.
//! It is not a general-purpose HTTP stack — hardening (keep-alive reuse, HTTP/2,
//! trailers) is out of scope for this MVP slice.

use tokio::io::{self, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt};

/// Hard ceiling on a single captured body held in memory (design §6.1 limits).
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Head {
    pub start_line: (String, String, String),
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// Case-insensitive single-header lookup.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read bytes up to and including the blank line terminating an HTTP head.
pub async fn read_head_bytes<R: AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = r.read_until(b'\n', &mut line).await?;
        if n == 0 {
            break; // EOF before terminator
        }
        head.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if head.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http head too large",
            ));
        }
    }
    Ok(head)
}

/// Parse a request/response head. Returns `None` if the start line is malformed.
pub fn parse_head(bytes: &[u8]) -> Option<Head> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let start = lines.next()?;
    let mut parts = start.splitn(3, ' ');
    let a = parts.next()?.to_string();
    let b = parts.next()?.to_string();
    let c = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some(Head {
        start_line: (a, b, c),
        headers,
    })
}

/// Read a message body according to its framing headers. For responses with
/// neither Content-Length nor chunked encoding, pass `read_until_eof = true`.
pub async fn read_body<R: AsyncBufRead + Unpin>(
    r: &mut R,
    head: &Head,
    read_until_eof: bool,
) -> io::Result<Vec<u8>> {
    if let Some(te) = head.get("transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return read_chunked(r).await;
        }
    }
    if let Some(cl) = head.get("content-length") {
        let n: usize = cl.trim().parse().unwrap_or(0);
        let n = n.min(MAX_BODY_BYTES);
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf).await?;
        return Ok(buf);
    }
    if read_until_eof {
        let mut buf = Vec::new();
        read_capped_to_end(r, &mut buf).await?;
        return Ok(buf);
    }
    Ok(Vec::new())
}

async fn read_capped_to_end<R: AsyncRead + Unpin>(r: &mut R, out: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0u8; 8192];
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_BODY_BYTES {
            out.extend_from_slice(&chunk[..MAX_BODY_BYTES - out.len()]);
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

async fn read_chunked<R: AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = Vec::new();
        let n = r.read_until(b'\n', &mut size_line).await?;
        if n == 0 {
            break;
        }
        let s = String::from_utf8_lossy(&size_line);
        let size =
            usize::from_str_radix(s.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 {
            // Consume trailers / final CRLF.
            loop {
                let mut l = Vec::new();
                let m = r.read_until(b'\n', &mut l).await?;
                if m == 0 || l == b"\r\n" || l == b"\n" {
                    break;
                }
            }
            break;
        }
        if body.len() + size > MAX_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body exceeds cap",
            ));
        }
        let mut buf = vec![0u8; size];
        r.read_exact(&mut buf).await?;
        body.extend_from_slice(&buf);
        let mut crlf = [0u8; 2];
        let _ = r.read_exact(&mut crlf).await; // trailing CRLF after chunk
    }
    Ok(body)
}

/// Split an absolute-form proxy target (`http://host:port/path`) into
/// (host, port, path-and-query).
pub fn parse_absolute_target(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // Drop any userinfo.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

/// Split a CONNECT target (`host:port`) into (host, port).
pub fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_target() {
        let (h, p, path) = parse_absolute_target("http://example.com/v1/x?y=1").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/v1/x?y=1");

        let (h, p, path) = parse_absolute_target("http://api.test:8080/a").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("api.test", 8080, "/a"));
    }

    #[test]
    fn parses_connect_target() {
        assert_eq!(
            parse_connect_target("example.com:443"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(parse_connect_target("nope"), None);
    }

    #[test]
    fn parses_head() {
        let raw = b"GET http://x/ HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n";
        let h = parse_head(raw).unwrap();
        assert_eq!(h.start_line.0, "GET");
        assert_eq!(h.get("content-length"), Some("3"));
        assert_eq!(h.get("HOST"), Some("x"));
    }
}
