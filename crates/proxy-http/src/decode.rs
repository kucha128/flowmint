//! 按 HTTP `Content-Encoding` 解压响应体。
//!
//! 抓包时存的是**原样转发给客户端的压缩字节**（保真、可重放），因此检查器展示
//! HTML/JS/JSON 前需要先解压，否则 gzip/br 流不是合法 UTF-8，只能显示成十六进制。
//! 解压失败时返回原始字节（宁可显示成二进制，也不隐藏数据）。

use std::io::Read;

/// 单次解压上限：防止解压炸弹（zip bomb）撑爆内存。
const MAX_DECODED: usize = 64 * 1024 * 1024;

/// 按 `Content-Encoding` 解压 `data`。支持 gzip / deflate / br / zstd，
/// 以及逗号分隔的多重编码（按从右到左的顺序逐层解开）。
/// `identity`、未知编码、空值或解压失败时，原样返回。
pub fn decode_body(content_encoding: Option<&str>, data: &[u8]) -> Vec<u8> {
    let Some(enc) = content_encoding else {
        return data.to_vec();
    };
    // 多重编码如 "gzip, br"：应用顺序与书写顺序相反，逐层剥离。
    let mut out = data.to_vec();
    for token in enc.split(',').rev() {
        match token.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => {}
            "gzip" | "x-gzip" => out = try_decode(&out, decode_gzip),
            "deflate" => out = try_decode(&out, decode_deflate),
            "br" => out = try_decode(&out, decode_brotli),
            "zstd" => out = try_decode(&out, decode_zstd),
            _ => return out, // 未知编码：无法继续，返回当前结果
        }
    }
    out
}

/// 解压一层；失败则退回该层的输入（不丢数据）。
fn try_decode(data: &[u8], f: fn(&[u8]) -> std::io::Result<Vec<u8>>) -> Vec<u8> {
    f(data).unwrap_or_else(|_| data.to_vec())
}

fn read_capped<R: Read>(r: R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.take(MAX_DECODED as u64).read_to_end(&mut out)?;
    Ok(out)
}

fn decode_gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    read_capped(flate2::read::GzDecoder::new(data))
}

/// HTTP `deflate` 现实中既有 zlib 包裹的，也有裸 deflate 的；先按 zlib 解，
/// 失败再按裸 deflate 解。
fn decode_deflate(data: &[u8]) -> std::io::Result<Vec<u8>> {
    read_capped(flate2::read::ZlibDecoder::new(data))
        .or_else(|_| read_capped(flate2::read::DeflateDecoder::new(data)))
}

fn decode_brotli(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    brotli::BrotliDecompress(&mut std::io::Cursor::new(data), &mut LimitedSink(&mut out))?;
    Ok(out)
}

fn decode_zstd(data: &[u8]) -> std::io::Result<Vec<u8>> {
    read_capped(zstd::stream::read::Decoder::new(data)?)
}

/// 给 brotli 的写出端加容量上限，防止解压炸弹。
struct LimitedSink<'a>(&'a mut Vec<u8>);
impl std::io::Write for LimitedSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.0.len() + buf.len() > MAX_DECODED {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "解压结果超过上限",
            ));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gzip_roundtrip() {
        let src = b"<html><body>hello flowmint</body></html>";
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(src).unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(decode_body(Some("gzip"), &gz), src);
    }

    #[test]
    fn passthrough_when_no_encoding() {
        assert_eq!(decode_body(None, b"plain"), b"plain");
        assert_eq!(decode_body(Some("identity"), b"plain"), b"plain");
    }

    #[test]
    fn unknown_encoding_returns_input() {
        assert_eq!(decode_body(Some("weird"), b"raw"), b"raw");
    }

    #[test]
    fn corrupt_gzip_returns_input() {
        // 非法 gzip：不应 panic，原样返回。
        assert_eq!(decode_body(Some("gzip"), b"not gzip"), b"not gzip");
    }
}
