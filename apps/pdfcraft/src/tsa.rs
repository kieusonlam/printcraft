//! The transport behind Preferences ▸ Timestamp server: one RFC 3161 request over HTTP(S)
//! (RFC 3161 §3.4), sent only when a digital signature is made and a server is set.
//!
//! What leaves the machine is the DER `TimeStampReq` alone: a SHA-256 hash of the signature value.
//! TLS goes through rustls with the OS's trusted roots, as Check for updates does.

use std::time::Duration;

/// A server that hasn't answered by then has failed; signing says so instead of hanging.
const TIMEOUT: Duration = Duration::from_secs(15);
/// The largest response read; a token with its certificate chain is a few kilobytes
/// (`pdfcraft_sign::timestamp` refuses anything over 4 MiB too).
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;

/// Send `request` to the timestamp server at `url` and return its `TimeStampResp`.
pub(crate) fn post(url: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    // The address is checked in Preferences already; checked again so nothing else is ever sent to.
    let url = match pdfcraft_ui_egui::timestamp_server(url) {
        Ok(Some(url)) => url,
        Ok(None) => return Err("no timestamp server is set".into()),
        Err(e) => return Err(e.into()),
    };
    let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
    let agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(TIMEOUT))
        .http_status_as_error(false)
        .user_agent(concat!("PdfCraft/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent();
    let mut resp = agent
        .post(&url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .send(request)
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    resp.body_mut().with_config().limit(MAX_RESPONSE).read_to_vec().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A one-request HTTP server on loopback: answers `status` with `body` and hands back what
    /// it was sent (headers lowercased, then the body).
    fn serve(status: &'static str, body: &'static [u8]) -> (String, std::thread::JoinHandle<(String, Vec<u8>)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/tsa", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (mut head, mut len) = (String::new(), 0usize);
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                head.push_str(&lower);
            }
            let mut sent = vec![0; len];
            reader.read_exact(&mut sent).unwrap();
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
            (head, sent)
        });
        (url, handle)
    }

    #[test]
    fn posts_the_request_as_a_timestamp_query_and_returns_the_reply() {
        let (url, server) = serve("200 OK", b"\x30\x03\x02\x01\x00");
        let reply = super::post(&url, b"\x30\x01\x00").unwrap();
        assert_eq!(reply, b"\x30\x03\x02\x01\x00");
        let (head, sent) = server.join().unwrap();
        assert!(head.starts_with("post /tsa "), "{head}");
        assert!(head.contains("content-type: application/timestamp-query"), "{head}");
        assert_eq!(sent, b"\x30\x01\x00", "the DER request, and nothing else");
    }

    #[test]
    fn an_http_error_is_an_error() {
        let (url, server) = serve("503 Service Unavailable", b"busy");
        assert_eq!(super::post(&url, b"\x30\x00"), Err("HTTP 503".into()));
        server.join().unwrap();
    }

    #[test]
    fn nothing_is_sent_to_an_address_that_isnt_http() {
        assert!(super::post("file:///etc/passwd", b"x").is_err());
        assert!(super::post("", b"x").is_err());
    }
}
