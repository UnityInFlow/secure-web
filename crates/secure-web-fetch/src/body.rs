//! Streaming body decoder with a hard cap on **decompressed** bytes (threat T9).
//!
//! Network chunks are pushed one at a time. Decompression happens here (never in the HTTP
//! client), into a sink that refuses the write that would cross the limit, so the decoded
//! buffer never holds more than `limit` bytes and the stream is abandoned at that point.

use std::io::{self, Write};

use flate2::write::{GzDecoder, ZlibDecoder};

use crate::content::Encoding;

/// Why the body could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyError {
    /// More than `limit` decoded bytes.
    TooLarge,
    /// The compressed stream is corrupt or has trailing data.
    Corrupt,
}

/// Error payload the sink returns when the cap is hit, so a limit breach can be told apart from
/// a corrupt stream even after the decoder is consumed.
#[derive(Debug)]
struct LimitExceeded;

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("decoded body exceeds the limit")
    }
}

impl std::error::Error for LimitExceeded {}

fn is_limit_exceeded(err: &io::Error) -> bool {
    err.get_ref()
        .is_some_and(|inner| inner.is::<LimitExceeded>())
}

/// Buffer that accepts at most `limit` bytes; the write that would exceed it fails and nothing
/// of it is kept.
struct CappedSink {
    buf: Vec<u8>,
    limit: u64,
    exceeded: bool,
}

impl Write for CappedSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let would_hold = (self.buf.len() as u64).saturating_add(data.len() as u64);
        if self.exceeded || would_hold > self.limit {
            self.exceeded = true;
            return Err(io::Error::other(LimitExceeded));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Decoder {
    Identity(CappedSink),
    Gzip(GzDecoder<CappedSink>),
    Deflate(ZlibDecoder<CappedSink>),
}

impl Decoder {
    fn sink(&self) -> &CappedSink {
        match self {
            Decoder::Identity(sink) => sink,
            Decoder::Gzip(decoder) => decoder.get_ref(),
            Decoder::Deflate(decoder) => decoder.get_ref(),
        }
    }
}

/// Incremental, bounded body decoder.
pub(crate) struct BoundedBody {
    decoder: Decoder,
    peak_buffered: u64,
}

impl BoundedBody {
    pub(crate) fn new(encoding: Encoding, limit: u64) -> Self {
        let sink = CappedSink {
            buf: Vec::new(),
            limit,
            exceeded: false,
        };
        let decoder = match encoding {
            Encoding::Identity => Decoder::Identity(sink),
            Encoding::Gzip => Decoder::Gzip(GzDecoder::new(sink)),
            Encoding::Deflate => Decoder::Deflate(ZlibDecoder::new(sink)),
        };
        Self {
            decoder,
            peak_buffered: 0,
        }
    }

    /// Decoded bytes held so far.
    pub(crate) fn decoded_len(&self) -> u64 {
        self.decoder.sink().buf.len() as u64
    }

    /// Largest `decoded bytes + current network chunk` seen so far.
    pub(crate) fn peak_buffered(&self) -> u64 {
        self.peak_buffered
    }

    /// Feed one network chunk.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        if self.decoder.sink().exceeded {
            return Err(BodyError::TooLarge);
        }
        let holding = self.decoded_len().saturating_add(chunk.len() as u64);
        self.peak_buffered = self.peak_buffered.max(holding);
        let result = match &mut self.decoder {
            Decoder::Identity(sink) => sink.write_all(chunk),
            Decoder::Gzip(decoder) => decoder.write_all(chunk),
            Decoder::Deflate(decoder) => decoder.write_all(chunk),
        };
        result.map_err(|_| self.classify())
    }

    /// End of stream: flush the decoder and return the decoded body.
    pub(crate) fn finish(self) -> Result<Vec<u8>, BodyError> {
        let finished = match self.decoder {
            Decoder::Identity(sink) => Ok(sink),
            Decoder::Gzip(decoder) => decoder.finish(),
            Decoder::Deflate(decoder) => decoder.finish(),
        };
        match finished {
            Ok(sink) if !sink.exceeded => Ok(sink.buf),
            Ok(_) => Err(BodyError::TooLarge),
            // The final flush can still produce output past the cap.
            Err(err) if is_limit_exceeded(&err) => Err(BodyError::TooLarge),
            Err(_) => Err(BodyError::Corrupt),
        }
    }

    fn classify(&self) -> BodyError {
        if self.decoder.sink().exceeded {
            BodyError::TooLarge
        } else {
            BodyError::Corrupt
        }
    }
}

#[cfg(test)]
mod tests {
    use flate2::write::{GzEncoder, ZlibEncoder};
    use flate2::Compression;

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn identity_body_up_to_the_limit_is_accepted() {
        let mut body = BoundedBody::new(Encoding::Identity, 10);
        body.push(b"hello").unwrap();
        body.push(b"world").unwrap();
        assert_eq!(body.finish().unwrap(), b"helloworld");
    }

    #[test]
    fn identity_body_past_the_limit_is_rejected_without_keeping_the_chunk() {
        let mut body = BoundedBody::new(Encoding::Identity, 10);
        body.push(b"hello").unwrap();
        assert_eq!(body.push(b"world!"), Err(BodyError::TooLarge));
        assert_eq!(body.decoded_len(), 5);
        assert_eq!(body.push(b""), Err(BodyError::TooLarge));
    }

    #[test]
    fn gzip_bomb_stops_at_the_limit() {
        let bomb = gzip(&vec![0u8; 10 * 1024 * 1024]);
        let limit = 64 * 1024;
        let mut body = BoundedBody::new(Encoding::Gzip, limit);
        let mut result = Ok(());
        for chunk in bomb.chunks(1024) {
            result = body.push(chunk);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(BodyError::TooLarge));
        assert!(body.decoded_len() <= limit);
        assert!(body.peak_buffered() <= limit + 1024);
    }

    #[test]
    fn gzip_and_deflate_round_trip() {
        let mut body = BoundedBody::new(Encoding::Gzip, 100);
        body.push(&gzip(b"compressed")).unwrap();
        assert_eq!(body.finish().unwrap(), b"compressed");

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"deflated").unwrap();
        let mut body = BoundedBody::new(Encoding::Deflate, 100);
        body.push(&encoder.finish().unwrap()).unwrap();
        assert_eq!(body.finish().unwrap(), b"deflated");
    }

    #[test]
    fn corrupt_gzip_is_not_too_large() {
        let mut body = BoundedBody::new(Encoding::Gzip, 100);
        let pushed = body.push(b"this is not gzip at all");
        let result = pushed.and_then(|()| body.finish().map(|_| ()));
        assert_eq!(result, Err(BodyError::Corrupt));
    }

    #[test]
    fn truncated_gzip_is_corrupt() {
        let full = gzip(b"some text that will be cut off");
        let mut body = BoundedBody::new(Encoding::Gzip, 100);
        body.push(&full[..full.len() / 2]).unwrap();
        assert_eq!(body.finish(), Err(BodyError::Corrupt));
    }
}
