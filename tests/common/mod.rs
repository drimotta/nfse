#![allow(dead_code)]
//! Test helpers: a SoftHSM token with an RSA key and certificate, made with
//! the softhsm2-util, openssl and pkcs11-tool commands. Tests that need them
//! are skipped when they are not installed.

use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";
pub const PIN: &str = "1234";

pub fn have(tools: &[&str]) -> bool {
    tools.iter().all(|t| {
        Command::new("which")
            .arg(t)
            .output()
            .is_ok_and(|o| o.status.success())
    }) && Path::new(&softhsm_module()).exists()
}

pub fn softhsm_module() -> String {
    std::env::var("SOFTHSM_MODULE").unwrap_or_else(|_| {
        [
            SOFTHSM,
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
        ]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or(SOFTHSM)
        .to_string()
    })
}

pub fn run(dir: &Path, cmd: &str, args: &[&str]) {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .env("SOFTHSM2_CONF", dir.join("softhsm2.conf"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{cmd} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A CA and a client certificate signed by it, with the key on a SoftHSM token.
pub struct TestToken {
    pub dir: tempfile::TempDir,
}

impl TestToken {
    pub fn new(always_auth: bool) -> TestToken {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir(d.join("tokens")).unwrap();
        std::fs::write(
            d.join("softhsm2.conf"),
            format!("directories.tokendir = {}\n", d.join("tokens").display()),
        )
        .unwrap();
        run(
            d,
            "softhsm2-util",
            &[
                "--init-token",
                "--free",
                "--label",
                "A3-TEST",
                "--pin",
                PIN,
                "--so-pin",
                "5678",
            ],
        );
        std::fs::write(
            d.join("ca.ext"),
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
        )
        .unwrap();
        std::fs::write(
            d.join("client.ext"),
            "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment\nextendedKeyUsage=clientAuth\n",
        )
        .unwrap();
        std::fs::write(
            d.join("server.ext"),
            "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n",
        )
        .unwrap();
        run(
            d,
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-subj",
                "/CN=Test CA",
                "-days",
                "2",
                "-out",
                "ca.pem",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        for name in ["client", "server"] {
            let cn = if name == "client" {
                "/C=BR/CN=EMPRESA TESTE:12345678000195"
            } else {
                "/CN=localhost"
            };
            run(
                d,
                "openssl",
                &[
                    "req",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    &format!("{name}.key"),
                    "-subj",
                    cn,
                    "-out",
                    &format!("{name}.csr"),
                ],
            );
            run(
                d,
                "openssl",
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-days",
                    "2",
                    "-extfile",
                    &format!("{name}.ext"),
                    "-out",
                    &format!("{name}.pem"),
                ],
            );
        }
        run(
            d,
            "openssl",
            &[
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                "server.key",
                "-out",
                "server.pk8",
            ],
        );
        run(
            d,
            "openssl",
            &[
                "pkey",
                "-in",
                "client.key",
                "-outform",
                "DER",
                "-out",
                "client.key.der",
            ],
        );
        run(
            d,
            "openssl",
            &[
                "x509",
                "-in",
                "client.pem",
                "-outform",
                "DER",
                "-out",
                "client.der",
            ],
        );
        let module = softhsm_module();
        let mut key_args = vec![
            "--module",
            &module,
            "--login",
            "--pin",
            PIN,
            "--write-object",
            "client.key.der",
            "--type",
            "privkey",
            "--id",
            "01",
            "--label",
            "signing",
        ];
        if always_auth {
            key_args.push("--always-auth");
        }
        run(d, "pkcs11-tool", &key_args);
        run(
            d,
            "pkcs11-tool",
            &[
                "--module",
                &module,
                "--login",
                "--pin",
                PIN,
                "--write-object",
                "client.der",
                "--type",
                "cert",
                "--id",
                "01",
                "--label",
                "signing",
            ],
        );
        // SoftHSM reads its configuration from the environment.
        unsafe { std::env::set_var("SOFTHSM2_CONF", d.join("softhsm2.conf")) };
        TestToken { dir }
    }

    /// Writes another key and certificate to the token.
    pub fn add_key(&self, id: &str, label: &str, key_der: &str, cert_der: &str) {
        let module = softhsm_module();
        let d = self.dir.path();
        for (file, ty) in [(key_der, "privkey"), (cert_der, "cert")] {
            run(
                d,
                "pkcs11-tool",
                &[
                    "--module",
                    &module,
                    "--login",
                    "--pin",
                    PIN,
                    "--write-object",
                    file,
                    "--type",
                    ty,
                    "--id",
                    id,
                    "--label",
                    label,
                ],
            );
        }
    }

    /// DER of a PEM certificate in the token directory.
    pub fn der(&self, pem: &str) -> Vec<u8> {
        let out = Command::new("openssl")
            .args(["x509", "-outform", "DER", "-in"])
            .arg(self.path(pem))
            .output()
            .unwrap();
        assert!(out.status.success());
        out.stdout
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

pub type Handler = Box<dyn Fn(&str, &str, &str) -> (u16, String, String) + Send + Sync>;

/// How the test server asks for the client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// In the first handshake.
    Initial,
    /// By renegotiating after reading the request, as Sefin does.
    Renegotiate,
}

#[derive(Default)]
pub struct Seen {
    pub requests: Vec<String>,
    /// Requests answered after a verified client certificate.
    pub authenticated: usize,
    pub versions: Vec<String>,
}

unsafe extern "C" {
    fn SSL_renegotiate(ssl: *mut openssl_sys::SSL) -> std::ffi::c_int;
    fn SSL_renegotiate_pending(ssl: *const openssl_sys::SSL) -> std::ffi::c_int;
}

/// Serves HTTPS on localhost (TLS 1.2 and 1.3 allowed), requiring a client
/// certificate from the test CA. `handler(method, path, body)` returns
/// (status, content type, body).
pub fn serve_with(t: &TestToken, auth: ClientAuth, handler: Handler) -> (String, Arc<Mutex<Seen>>) {
    use foreign_types::ForeignTypeRef;
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    b.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    b.set_certificate_chain_file(t.path("server.pem")).unwrap();
    b.set_private_key_file(t.path("server.key"), openssl::ssl::SslFiletype::PEM)
        .unwrap();
    b.set_ca_file(t.path("ca.pem")).unwrap();
    // Required to verify client certificates on resumable sessions.
    b.set_session_id_context(b"nfse-test").unwrap();
    // A renegotiation must be a full handshake, or no certificate is sent.
    b.set_options(openssl::ssl::SslOptions::NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    if auth == ClientAuth::Initial {
        b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    let acceptor = Arc::new(b.build());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(mut tls) = acceptor.accept(stream) else {
                continue;
            };
            let mut reader = BufReader::new(&mut tls);
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                continue;
            }
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            drop(reader);
            if auth == ClientAuth::Renegotiate {
                // SAFETY: plain OpenSSL calls on a live connection.
                unsafe {
                    let raw = tls.ssl().as_ptr();
                    openssl_sys::SSL_set_verify(
                        raw,
                        (SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT).bits(),
                        None,
                    );
                    assert_eq!(SSL_renegotiate(raw), 1);
                    // Send HelloRequest, then let reads drive the new
                    // handshake (without auto-retry they return once the
                    // handshake records are processed).
                    let mut ok = openssl_sys::SSL_do_handshake(raw) == 1;
                    openssl_sys::SSL_ctrl(
                        raw,
                        78, /* SSL_CTRL_CLEAR_MODE */
                        4,  /* SSL_MODE_AUTO_RETRY */
                        std::ptr::null_mut(),
                    );
                    let mut buf = [0u8; 1];
                    for _ in 0..20 {
                        if !ok || SSL_renegotiate_pending(raw) == 0 {
                            break;
                        }
                        let r = openssl_sys::SSL_peek(raw, buf.as_mut_ptr() as *mut _, 1);
                        let err = openssl_sys::SSL_get_error(raw, r);
                        ok = r > 0 || err == openssl_sys::SSL_ERROR_WANT_READ;
                    }
                    ok = ok && SSL_renegotiate_pending(raw) == 0;
                    if !ok {
                        eprintln!(
                            "test server: renegotiation failed: {}",
                            openssl::error::ErrorStack::get()
                        );
                        continue; // drop the connection, like a reset
                    }
                }
            }
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            {
                let mut s = seen2.lock().unwrap();
                s.requests.push(format!("{} {}", parts[0], parts[1]));
                if tls.ssl().peer_certificate().is_some()
                    && tls.ssl().verify_result() == openssl::x509::X509VerifyResult::OK
                {
                    s.authenticated += 1;
                }
                s.versions.push(tls.ssl().version_str().to_string());
            }
            let (status, ctype, resp) =
                handler(parts[0], parts[1], &String::from_utf8_lossy(&body));
            let _ = write!(
                tls,
                "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                resp.len()
            );
            let _ = tls.flush();
            let _ = tls.shutdown();
        }
    });
    (format!("https://localhost:{port}"), seen)
}

/// The server as Sefin behaves: the certificate is asked by renegotiation.
pub fn serve(t: &TestToken, handler: Handler) -> (String, Arc<Mutex<Seen>>) {
    serve_with(t, ClientAuth::Renegotiate, handler)
}
