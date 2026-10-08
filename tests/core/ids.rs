//! Id format contract: `crawl_<12 hex>`, `open_<12 hex>`, `doc_<6 digits>`.
//!
//! Ids end up in file-system paths (`runs/<runId>/`) and MCP inputs (`web_find.crawlId`), so
//! parsing must be strict: anything that is not exactly the documented shape is rejected.

use std::collections::HashSet;

use secure_web_core::ids::{CrawlId, DocumentId, IdError, RunId};

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[test]
fn crawl_id_has_prefix_and_twelve_lowercase_hex() {
    let id = CrawlId::generate().unwrap();
    let s = id.as_str();
    let hex = s.strip_prefix("crawl_").unwrap();
    assert_eq!(hex.len(), 12, "{s}");
    assert!(is_lower_hex(hex), "{s}");
}

#[test]
fn open_run_id_has_prefix_and_twelve_lowercase_hex() {
    let id = RunId::generate_open().unwrap();
    let s = id.as_str();
    let hex = s.strip_prefix("open_").unwrap();
    assert_eq!(hex.len(), 12, "{s}");
    assert!(is_lower_hex(hex), "{s}");
}

#[test]
fn generated_ids_are_unique() {
    let ids: HashSet<String> = (0..1000)
        .map(|_| CrawlId::generate().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 1000);
}

#[test]
fn document_id_is_zero_padded_six_digits() {
    assert_eq!(DocumentId::from_seq(1).unwrap().as_str(), "doc_000001");
    assert_eq!(DocumentId::from_seq(42).unwrap().as_str(), "doc_000042");
    assert_eq!(
        DocumentId::from_seq(999_999).unwrap().as_str(),
        "doc_999999"
    );
}

#[test]
fn document_id_rejects_out_of_range_sequence() {
    assert!(matches!(
        DocumentId::from_seq(0),
        Err(IdError::SequenceOutOfRange(0))
    ));
    assert!(matches!(
        DocumentId::from_seq(1_000_000),
        Err(IdError::SequenceOutOfRange(1_000_000))
    ));
}

#[test]
fn run_id_wraps_a_crawl_id_verbatim() {
    let crawl = CrawlId::generate().unwrap();
    let run = RunId::from(crawl.clone());
    assert_eq!(run.as_str(), crawl.as_str());
}

#[test]
fn ids_round_trip_through_parse() {
    let crawl = CrawlId::generate().unwrap();
    assert_eq!(CrawlId::parse(crawl.as_str()).unwrap(), crawl);
    let open = RunId::generate_open().unwrap();
    assert_eq!(RunId::parse(open.as_str()).unwrap(), open);
    assert_eq!(
        RunId::parse(crawl.as_str()).unwrap().as_str(),
        crawl.as_str()
    );
    let doc = DocumentId::from_seq(7).unwrap();
    assert_eq!(DocumentId::parse(doc.as_str()).unwrap(), doc);
}

#[test]
fn parse_rejects_malformed_ids() {
    let bad_crawl = [
        "",
        "crawl_",
        "crawl_abc",
        "crawl_0123456789ab0",  // 13 hex
        "crawl_0123456789AB",   // uppercase
        "crawl_0123456789ag",   // non-hex
        "open_0123456789ab",    // wrong prefix
        "crawl_../../etc/pas",  // traversal
        " crawl_0123456789ab",  // whitespace
        "crawl_0123456789ab\n", // trailing newline
        "crawl_٠١٢٣٤٥٦٧٨٩ab",   // non-ASCII digits
    ];
    for s in bad_crawl {
        assert!(CrawlId::parse(s).is_err(), "CrawlId accepted {s:?}");
    }
    let bad_run = [
        "",
        "open_",
        "open_0123456789a",
        "doc_000001",
        "open_../0123456789",
    ];
    for s in bad_run {
        assert!(RunId::parse(s).is_err(), "RunId accepted {s:?}");
    }
    let bad_doc = [
        "",
        "doc_",
        "doc_1",
        "doc_0000001",
        "doc_000000",
        "doc_00000a",
        "doc_-00001",
        "DOC_000001",
    ];
    for s in bad_doc {
        assert!(DocumentId::parse(s).is_err(), "DocumentId accepted {s:?}");
    }
}

#[test]
fn ids_serialize_as_plain_strings_and_validate_on_deserialize() {
    let doc = DocumentId::from_seq(3).unwrap();
    assert_eq!(serde_json::to_string(&doc).unwrap(), "\"doc_000003\"");
    let back: DocumentId = serde_json::from_str("\"doc_000003\"").unwrap();
    assert_eq!(back, doc);
    assert!(serde_json::from_str::<DocumentId>("\"doc_3\"").is_err());
    assert!(serde_json::from_str::<CrawlId>("\"crawl_../../x\"").is_err());
    assert!(serde_json::from_str::<RunId>("\"open_zzzzzzzzzzzz\"").is_err());
}
