//! The nfse binary end to end: SoftHSM token, local HTTPS server standing in
//! for Sefin and ADN.

mod common;

use common::*;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

const INPUT: &str = include_str!("../examples/input.json");

fn nfse(
    t: Option<&TestToken>,
    base: Option<&str>,
    args: &[&str],
    stdin: &str,
    cwd: &std::path::Path,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nfse"));
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for k in [
        "NFSE_PKCS11_MODULE",
        "NFSE_PIN",
        "NFSE_CA_BUNDLE",
        "NFSE_SEFIN_URL",
        "NFSE_ADN_URL",
    ] {
        cmd.env_remove(k);
    }
    if let Some(t) = t {
        cmd.env("SOFTHSM2_CONF", t.path("softhsm2.conf"))
            .env("NFSE_PKCS11_MODULE", softhsm_module())
            .env("NFSE_PIN", PIN)
            .env("NFSE_CA_BUNDLE", t.path("ca.pem"));
    }
    if let Some(base) = base {
        cmd.env("NFSE_SEFIN_URL", format!("{base}/SefinNacional"))
            .env("NFSE_ADN_URL", base);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn dry_run_prints_the_unsigned_dps() {
    let dir = tempfile::tempdir().unwrap();
    let out = nfse(None, None, &["--dry-run"], INPUT, dir.path());
    assert!(out.status.success(), "{}", text(&out.stderr));
    let xml = text(&out.stdout);
    assert!(xml.contains("<tpAmb>2</tpAmb>"), "{xml}");
    assert!(
        xml.contains(&format!(
            "<serie>{}</serie>",
            chrono::Utc::now().format("%Y")
        )) || xml.contains("-12-31T"),
        "{xml}"
    );
    assert!(!xml.contains("<Signature"));
    assert!(text(&out.stderr).contains("DPS id: DPS3106200212345678000195"));
}

#[test]
fn missing_fields_are_listed() {
    let dir = tempfile::tempdir().unwrap();
    let out = nfse(
        None,
        None,
        &["--dry-run"],
        r#"{"dCompet":"2026-11-01"}"#,
        dir.path(),
    );
    assert!(!out.status.success());
    let err = text(&out.stderr);
    assert!(
        err.contains("prest: required") && err.contains("serv: required"),
        "{err}"
    );
}

#[test]
fn reuse_with_an_override() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = format!(
        "{}/tests/fixtures/nfse-ibscbs.xml",
        env!("CARGO_MANIFEST_DIR")
    );
    let out = nfse(
        None,
        None,
        &["--dry-run", "--reuse", &fixture],
        r#"{"valores":{"vServPrest":{"vServ":"1234.56"}}}"#,
        dir.path(),
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let xml = text(&out.stdout);
    assert!(
        xml.contains("<vServ>1234.56</vServ>") && xml.contains("<xNome>Example Corp</xNome>"),
        "{xml}"
    );
}

#[test]
fn signs_submits_and_saves_xml_and_pdf() {
    if !have(&["softhsm2-util", "pkcs11-tool", "openssl"]) {
        eprintln!("skipped: SoftHSM, OpenSC tools or openssl not installed");
        return;
    }
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = TestToken::new(false);
    let dir = tempfile::tempdir().unwrap();

    // Without --submit: the signed DPS.
    let out = nfse(Some(&t), None, &[], INPUT, dir.path());
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("<SignatureValue>"));

    let (base, seen) = serve(
        &t,
        Box::new(|method, path, _| match (method, path) {
            ("POST", "/SefinNacional/nfse") => (
                201,
                "application/json".into(),
                format!(
                    r#"{{"chaveAcesso":"K9","nfseXmlGZipB64":"{}"}}"#,
                    nfse::connector::gzip_b64(b"<NFSe>issued</NFSe>")
                ),
            ),
            ("GET", "/danfse/K9") => (200, "application/pdf".into(), "%PDF-1.4 test".into()),
            _ => (404, "text/plain".into(), String::new()),
        }),
    );
    let out = nfse(
        Some(&t),
        Some(&base),
        &["--submit", "--xml-outfile", "--pdf-outfile"],
        INPUT,
        dir.path(),
    );
    let err = text(&out.stderr);
    assert!(out.status.success(), "{err}");
    let id = err
        .lines()
        .find_map(|l| l.strip_prefix("DPS id: "))
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(
        std::fs::read_to_string(dir.path().join(format!("{id}.xml"))).unwrap(),
        "<NFSe>issued</NFSe>"
    );
    assert_eq!(
        std::fs::read(dir.path().join(format!("{id}.pdf"))).unwrap(),
        b"%PDF-1.4 test"
    );
    assert_eq!(
        seen.lock().unwrap().requests,
        ["POST /SefinNacional/nfse", "GET /danfse/K9"]
    );
}
