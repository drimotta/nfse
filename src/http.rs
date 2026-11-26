//! A minimal HTTP/1.1 client over OpenSSL: one request per connection
//! (`Connection: close`), Content-Length or chunked bodies.

use crate::tls::TokenTls;
use anyhow::{Context, Result, anyhow, bail};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub struct Client {
    tls: TokenTls,
    pub connect_timeout: Duration,
    pub timeout: Duration,
}

/// `https://host[:port]/path` split into (host, port, path).
pub fn split_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("only https URLs are supported: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().with_context(|| format!("bad port in {url}"))?),
        None => (authority, 443),
    };
    if host.is_empty() {
        bail!("no host in {url}");
    }
    Ok((host.to_string(), port, path.to_string()))
}

impl Client {
    pub fn new(tls: TokenTls) -> Client {
        Client {
            tls,
            connect_timeout: Duration::from_secs(10),
            timeout: Duration::from_secs(60),
        }
    }

    /// Sends one request. Any error means the outcome is unknown.
    pub fn request(
        &self,
        method: &str,
        url: &str,
        accept: &str,
        json_body: Option<&[u8]>,
    ) -> Result<Response> {
        let (host, port, path) = split_url(url)?;
        let addrs: Vec<_> = (host.as_str(), port)
            .to_socket_addrs()
            .with_context(|| format!("cannot resolve {host}"))?
            .collect();
        let mut last = anyhow!("no address for {host}");
        let mut tcp = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = anyhow!("cannot connect to {addr}: {e}"),
            }
        }
        let tcp = tcp.ok_or(last)?;
        tcp.set_read_timeout(Some(self.timeout))?;
        tcp.set_write_timeout(Some(self.timeout))?;
        let mut tls = self
            .tls
            .connector
            .connect(&host, tcp)
            .map_err(|e| anyhow!("TLS handshake with {host} failed: {e}"))?;

        let host_header = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: {accept}\r\nUser-Agent: nfse-cli/{}\r\nConnection: close\r\n",
            env!("CARGO_PKG_VERSION")
        );
        if let Some(body) = json_body {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        tls.write_all(head.as_bytes())?;
        if let Some(body) = json_body {
            tls.write_all(body)?;
        }
        tls.flush()?;
        read_response(BufReader::new(tls)).with_context(|| format!("{method} {url}"))
    }
}

fn read_line(r: &mut impl BufRead) -> Result<String> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

pub fn read_response(mut r: impl BufRead) -> Result<Response> {
    let status_line = read_line(&mut r).context("no response from the server")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad status line {status_line:?}"))?;
    let mut length = None;
    let mut chunked = false;
    loop {
        let line = read_line(&mut r)?;
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => {
                    length = Some(value.parse::<usize>().context("bad Content-Length")?)
                }
                "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
                _ => {}
            }
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let size_line = read_line(&mut r)?;
            let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
                .with_context(|| format!("bad chunk size {size_line:?}"))?;
            if size == 0 {
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            r.read_exact(&mut body[start..])?;
            read_line(&mut r)?;
        }
    } else if let Some(n) = length {
        body.resize(n, 0);
        r.read_exact(&mut body)?;
    } else {
        // Body until the connection closes; a missing close_notify is fine here.
        let _ = r.read_to_end(&mut body);
    }
    Ok(Response { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls() {
        assert_eq!(
            split_url("https://a.b/c/d").unwrap(),
            ("a.b".into(), 443, "/c/d".into())
        );
        assert_eq!(
            split_url("https://localhost:8443").unwrap(),
            ("localhost".into(), 8443, "/".into())
        );
        assert!(split_url("http://a").is_err());
    }

    #[test]
    fn reads_content_length_and_chunked_bodies() {
        let r = read_response(&b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nokEXTRA"[..])
            .unwrap();
        assert_eq!((r.status, r.body), (201, b"ok".to_vec()));
        let r = read_response(&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n"[..]).unwrap();
        assert_eq!(r.body, b"abcde");
        let r = read_response(&b"HTTP/1.1 404 Not Found\r\n\r\nrest"[..]).unwrap();
        assert_eq!((r.status, r.text()), (404, "rest".into()));
    }
}
