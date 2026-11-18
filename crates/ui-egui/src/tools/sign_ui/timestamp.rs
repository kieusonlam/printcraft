//! Preferences ▸ Fill & Sign ▸ Timestamp server: an RFC 3161 authority that stamps every digital
//! signature (PAdES B-T), so the signing time comes from the server, not this computer's clock.
//!
//! This crate opens no sockets: the desktop app supplies the transport (as it supplies the update
//! check), and the web build supplies none, so the setting is hidden there. Empty by default, and
//! while it is empty signing never touches the network. Only the RFC 3161 request leaves the
//! machine: a SHA-256 hash of the signature value. Never the document.

use std::sync::Arc;

use pdfcraft_engine::sign::{SignError, TimestampAuthority};

use crate::PdfCraftApp;

/// Sends one DER `TimeStampReq` to the server at the given address and returns its DER
/// `TimeStampResp`, or says why it couldn't.
pub type TimestampTransport = Arc<dyn Fn(&str, &[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// The longest server address kept (typed or restored).
pub const MAX_TIMESTAMP_SERVER_CHARS: usize = 2048;

/// A public RFC 3161 server offered in Preferences, so it needn't be typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimestampPreset {
    /// Who runs it, as shown in the list (a proper name: not translated).
    pub name: &'static str,
    pub url: &'static str,
}

/// Servers that answer anonymous RFC 3161 requests over plain HTTP (checked 2026-11-18 with a
/// SHA-256 request: status granted, a token signed by a certificate whose extended key usage is
/// time stamping). The Vietnamese Government CA's server comes first; both of its addresses reach
/// the same server ("Máy chủ cấp dấu thời gian 02", under "RootCA chuyên dùng Chính phủ G2").
/// `tsa::tests::every_preset_answers_with_a_valid_token` in the desktop app checks them again.
pub const TIMESTAMP_PRESETS: &[TimestampPreset] = &[
    TimestampPreset { name: "Ban Cơ yếu Chính phủ (VGCA)", url: "http://ca.gov.vn/tsa" },
    TimestampPreset { name: "Ban Cơ yếu Chính phủ (VGCA), tsa.ca.gov.vn", url: "http://tsa.ca.gov.vn" },
    TimestampPreset { name: "DigiCert", url: "http://timestamp.digicert.com" },
    TimestampPreset { name: "Sectigo", url: "http://timestamp.sectigo.com" },
];

/// The preset that `text` names, if any (compared as [`timestamp_server`] keeps it).
pub fn timestamp_preset(text: &str) -> Option<&'static TimestampPreset> {
    let url = timestamp_server(text).ok().flatten()?;
    TIMESTAMP_PRESETS.iter().find(|p| p.url.eq_ignore_ascii_case(&url))
}

/// The server address to use, trimmed; `None` for an empty box. Only `http://` and `https://`
/// addresses, as RFC 3161 servers are reached over HTTP (§3.4). Restored settings are untrusted.
pub fn timestamp_server(text: &str) -> Result<Option<String>, &'static str> {
    let url = text.trim();
    if url.is_empty() {
        return Ok(None);
    }
    if url.chars().count() > MAX_TIMESTAMP_SERVER_CHARS {
        return Err("The timestamp server address is too long.");
    }
    let lower = url.to_ascii_lowercase();
    let host = lower.strip_prefix("https://").or_else(|| lower.strip_prefix("http://"));
    match host {
        Some(rest) if !rest.is_empty() && !rest.starts_with('/') && !url.chars().any(char::is_whitespace) => Ok(Some(url.to_string())),
        _ => Err("Enter an address that starts with http:// or https://."),
    }
}

/// The configured server, reached through the app's transport.
pub(crate) struct ServerTsa {
    pub(crate) url: String,
    pub(crate) send: TimestampTransport,
}

impl TimestampAuthority for ServerTsa {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        (self.send)(&self.url, request).map_err(|e| SignError::Pdf(format!("The timestamp server {} did not answer: {e}", self.url)))
    }
}

impl PdfCraftApp {
    /// Lets digital signatures carry a timestamp from Preferences ▸ Timestamp server, sent through
    /// `transport`. Without one (the web build, tests) the setting is hidden and never used.
    pub fn set_timestamp_transport(&mut self, transport: TimestampTransport) {
        self.timestamp_transport = Some(transport);
    }

    /// Whether this build can reach a timestamp server at all.
    pub fn can_timestamp(&self) -> bool {
        self.timestamp_transport.is_some()
    }

    /// The authority to stamp the next signature with: the configured server, when there is
    /// one and a transport to reach it.
    pub(crate) fn timestamp_authority(&self) -> Option<ServerTsa> {
        let send = self.timestamp_transport.clone()?;
        let url = timestamp_server(&self.timestamp_server).ok().flatten()?;
        Some(ServerTsa { url, send })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_http_and_https_addresses_are_servers() {
        assert_eq!(timestamp_server(""), Ok(None));
        assert_eq!(timestamp_server("   "), Ok(None));
        assert_eq!(timestamp_server(" http://tsa.example.vn/tsa "), Ok(Some("http://tsa.example.vn/tsa".into())));
        assert_eq!(timestamp_server("HTTPS://tsa.example.vn"), Ok(Some("HTTPS://tsa.example.vn".into())));
        for bad in ["tsa.example.vn", "ftp://tsa.example.vn", "file:///etc/passwd", "https://", "http:///x", "https://a b"] {
            assert!(timestamp_server(bad).is_err(), "{bad}");
        }
        assert!(timestamp_server(&format!("https://{}", "a".repeat(MAX_TIMESTAMP_SERVER_CHARS))).is_err());
    }

    #[test]
    fn presets_are_valid_distinct_servers_and_are_recognised() {
        for p in TIMESTAMP_PRESETS {
            assert_eq!(timestamp_server(p.url), Ok(Some(p.url.to_string())), "{}", p.name);
            assert_eq!(timestamp_preset(&format!(" {} ", p.url.to_uppercase())), Some(p));
        }
        let mut urls: Vec<&str> = TIMESTAMP_PRESETS.iter().map(|p| p.url).collect();
        urls.sort_unstable();
        urls.dedup();
        assert_eq!(urls.len(), TIMESTAMP_PRESETS.len());
        assert_eq!(timestamp_preset("https://tsa.example.vn"), None);
        assert_eq!(timestamp_preset(""), None);
    }

    #[test]
    fn no_transport_means_no_timestamp_even_with_a_server() {
        let mut app = PdfCraftApp::new();
        app.timestamp_server = "https://tsa.example.vn".into();
        assert!(!app.can_timestamp());
        assert!(app.timestamp_authority().is_none());
        app.set_timestamp_transport(Arc::new(|_, _| Err("offline".into())));
        let tsa = app.timestamp_authority().map(|t| t.url);
        assert_eq!(tsa.as_deref(), Some("https://tsa.example.vn"));
        app.timestamp_server = "not a url".into();
        assert!(app.timestamp_authority().is_none(), "an invalid address is never sent to");
    }

    #[test]
    fn a_transport_error_names_the_server() {
        let tsa = ServerTsa { url: "https://tsa.example.vn".into(), send: Arc::new(|_, _| Err("timed out".into())) };
        let e = tsa.timestamp(b"req").err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("https://tsa.example.vn") && e.contains("timed out"), "{e}");
    }
}
