//! Minimal RFC 6455 WebSocket frame parsing for capture (design §3 WS row).
//!
//! Enough to decode frames off a decrypted/plain byte stream into a timeline of
//! text/binary/control messages. Used by the proxy to record `WebSocketFrame`
//! events after a 101 upgrade.

use tokio::io::{self, AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved(u8),
}

impl Opcode {
    fn from_u8(v: u8) -> Self {
        match v {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            other => Opcode::Reserved(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Opcode::Continuation => "continuation",
            Opcode::Text => "text",
            Opcode::Binary => "binary",
            Opcode::Close => "close",
            Opcode::Ping => "ping",
            Opcode::Pong => "pong",
            Opcode::Reserved(_) => "reserved",
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
            Opcode::Reserved(v) => *v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub masked: bool,
    pub payload: Vec<u8>,
}

/// Read one WebSocket frame from `r`. Returns `Ok(None)` on clean EOF.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut first2 = [0u8; 2];
    match r.read_exact(&mut first2).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let fin = first2[0] & 0x80 != 0;
    let opcode = Opcode::from_u8(first2[0] & 0x0F);
    let masked = first2[1] & 0x80 != 0;
    let len7 = first2[1] & 0x7F;

    let payload_len: usize = match len7 {
        126 => {
            let mut b = [0u8; 2];
            r.read_exact(&mut b).await?;
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b).await?;
            u64::from_be_bytes(b) as usize
        }
        n => n as usize,
    };

    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask).await?;
    }

    // Guard against absurd frames (design §6.1 limits).
    if payload_len > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ws frame too large",
        ));
    }
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload).await?;
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }

    Ok(Some(Frame {
        fin,
        opcode,
        masked,
        payload,
    }))
}

impl Opcode {
    fn to_u8(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
            Opcode::Reserved(v) => v,
        }
    }
}

/// Serialize a frame back to bytes. `mask` re-masks the payload with the given
/// key (client→server frames must be masked; server→client must not).
pub fn encode_frame(frame: &Frame, mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.payload.len() + 8);
    out.push(if frame.fin { 0x80 } else { 0 } | frame.opcode.to_u8());

    let len = frame.payload.len();
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len < 65536 {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(
                frame
                    .payload
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % 4]),
            );
        }
        None => out.extend_from_slice(&frame.payload),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encode_then_read_roundtrips() {
        let frame = Frame {
            fin: true,
            opcode: Opcode::Text,
            masked: true,
            payload: b"hello world".to_vec(),
        };
        let bytes = encode_frame(&frame, Some([1, 2, 3, 4]));
        let mut cursor = std::io::Cursor::new(bytes);
        let back = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(back.opcode, Opcode::Text);
        assert_eq!(back.payload, b"hello world");

        // Larger unmasked payload uses extended length.
        let big = Frame {
            fin: true,
            opcode: Opcode::Binary,
            masked: false,
            payload: vec![7u8; 500],
        };
        let bytes = encode_frame(&big, None);
        let mut cursor = std::io::Cursor::new(bytes);
        let back = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(back.payload.len(), 500);
    }

    #[tokio::test]
    async fn reads_masked_text_frame() {
        // A masked "Hi" text frame (client -> server).
        let mask = [0x37u8, 0xfa, 0x21, 0x3d];
        let data = b"Hi";
        let masked: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        let mut buf = vec![0x81u8, 0x80 | 2];
        buf.extend_from_slice(&mask);
        buf.extend_from_slice(&masked);

        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).await.unwrap().unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Text);
        assert!(frame.masked);
        assert_eq!(frame.payload, b"Hi");
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }
}
