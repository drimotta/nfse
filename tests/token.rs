//! Signing with a key on a PKCS#11 token (SoftHSM), checked by xmlsec1.

mod common;

use chrono::TimeZone;
use common::*;
use nfse::dps::{Environment, brt, build_dps, sign_dps};
use nfse::input::{combine, infdps_from_xml};
use nfse::pkcs11::{Selection, Token};
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

// SOFTHSM2_CONF is process-wide, so the token tests run one at a time.
static LOCK: Mutex<()> = Mutex::new(());

fn signed_dps(token: &Token) -> String {
    let xml = include_str!("fixtures/nfse-ibscbs.xml");
    let content = combine(
        Some(infdps_from_xml(xml).unwrap()),
        &Default::default(),
        Environment::Staging,
    )
    .unwrap();
    let now = brt().with_ymd_and_hms(2026, 11, 26, 10, 5, 9).unwrap();
    let dps = build_dps(&content, Environment::Staging, now).unwrap();
    sign_dps(&dps, token).unwrap()
}

fn verify(dir: &Path, signed: &str) {
    let file = dir.join("signed.xml");
    std::fs::write(&file, signed).unwrap();
    let out = Command::new("xmlsec1")
        .args(["--verify", "--trusted-pem"])
        .arg(dir.join("ca.pem"))
        .args(["--id-attr:Id", "infDPS"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "xmlsec1: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The signed DPS against the official XSD of its environment.
fn validate_xsd(dir: &Path, signed: &str, env: &str) {
    let file = dir.join("signed-xsd.xml");
    std::fs::write(&file, signed).unwrap();
    let xsd = format!("{}/xsd/{env}/DPS_v1.01.xsd", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("xmllint")
        .args(["--noout", "--schema", &xsd])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{env} XSD: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn check(always_auth: bool) {
    if !have(&["softhsm2-util", "pkcs11-tool", "openssl", "xmlsec1"]) {
        eprintln!("skipped: SoftHSM, OpenSC tools, openssl or xmlsec1 not installed");
        return;
    }
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = TestToken::new(always_auth);
    let token = Token::open(Path::new(&softhsm_module()), &Selection::default(), || {
        Ok(PIN.to_string())
    })
    .unwrap();
    let signed = signed_dps(&token);
    verify(t.dir.path(), &signed);
    if have(&["xmllint"]) {
        validate_xsd(t.dir.path(), &signed, "staging");
    }
}

#[test]
fn signed_dps_verifies() {
    check(false);
}

#[test]
fn signed_dps_verifies_with_always_authenticate_key() {
    check(true);
}

#[test]
fn wrong_token_label_is_reported() {
    if !have(&["softhsm2-util", "pkcs11-tool", "openssl"]) {
        return;
    }
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _t = TestToken::new(false);
    let selection = Selection {
        token_label: Some("nope".into()),
        ..Default::default()
    };
    let err = Token::open(Path::new(&softhsm_module()), &selection, || Ok(PIN.into()))
        .unwrap_err()
        .to_string();
    assert!(err.contains("A3-TEST"), "{err}");
}

mod key_choice {
    use super::*;
    use cryptoki::object::ObjectHandle;
    use nfse::pkcs11::{Candidate, CertInfo, choose_key};

    fn cand(n: u64, id: &[u8], label: &str, cert: &[u8]) -> Candidate {
        // SAFETY: test-only handles, never passed to a module.
        Candidate {
            key: unsafe { ObjectHandle::new_from_raw(n as _) },
            id: id.to_vec(),
            label: label.into(),
            cert: cert.to_vec(),
        }
    }

    /// The token, and the client, CA and server certificates (DER).
    type Certs = (TestToken, Vec<u8>, Vec<u8>, Vec<u8>);

    fn certs() -> Option<Certs> {
        if !have(&["softhsm2-util", "pkcs11-tool", "openssl"]) {
            return None;
        }
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let t = TestToken::new(false);
        let (client, ca, server) = (t.der("client.pem"), t.der("ca.pem"), t.der("server.pem"));
        Some((t, client, ca, server))
    }

    #[test]
    fn cert_info() {
        let Some((_t, client, ca, server)) = certs() else {
            return;
        };
        let c = CertInfo::parse(&client).unwrap();
        assert!(
            !c.is_ca && c.valid_now && c.digital_signature && c.client_auth == Some(true),
            "{c:?}"
        );
        assert!(CertInfo::parse(&ca).unwrap().is_ca);
        assert_eq!(CertInfo::parse(&server).unwrap().client_auth, Some(false));
    }

    #[test]
    fn keys_with_the_same_label_and_certificate_are_one_key() {
        let Some((_t, client, _, _)) = certs() else {
            return;
        };
        let label = "an ias rsa Private key";
        let chosen = choose_key(
            vec![
                cand(1, b"\x01", label, &client),
                cand(2, b"\x02", label, &client),
            ],
            &Selection::default(),
        )
        .unwrap();
        assert_eq!(chosen.id, b"\x01");
    }

    #[test]
    fn the_key_whose_certificate_fits_is_chosen() {
        let Some((_t, client, ca, server)) = certs() else {
            return;
        };
        let label = "an ias rsa Private key";
        let found = vec![
            cand(1, b"\x01", label, &ca),
            cand(2, b"\x02", label, &server),
            cand(3, b"\x03", label, &client),
        ];
        assert_eq!(
            choose_key(found, &Selection::default()).unwrap().id,
            b"\x03"
        );
    }

    #[test]
    fn two_usable_keys_need_an_id_and_the_id_selects() {
        let Some((t, client, _, _)) = certs() else {
            return;
        };
        // A second usable client certificate.
        run(
            t.dir.path(),
            "openssl",
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "c2.key",
                "-subj",
                "/CN=SECOND",
                "-out",
                "c2.csr",
            ],
        );
        run(
            t.dir.path(),
            "openssl",
            &[
                "x509",
                "-req",
                "-in",
                "c2.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "2",
                "-extfile",
                "client.ext",
                "-out",
                "c2.pem",
            ],
        );
        let second = t.der("c2.pem");
        let found = vec![
            cand(1, b"\xab\x01", "k", &client),
            cand(2, b"\xab\x02", "k", &second),
        ];
        let err = choose_key(found.clone(), &Selection::default())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("NFSE_KEY_ID")
                && err.contains("ab01")
                && err.contains("ab02")
                && err.contains("SECOND"),
            "{err}"
        );
        let sel = Selection {
            key_id: Some("AB02".into()),
            ..Default::default()
        };
        assert_eq!(choose_key(found.clone(), &sel).unwrap().id, b"\xab\x02");
        let sel = Selection {
            key_id: Some("ff".into()),
            ..Default::default()
        };
        assert!(
            choose_key(found, &sel)
                .unwrap_err()
                .to_string()
                .contains("no key with id ff")
        );
    }

    #[test]
    fn token_with_a_duplicate_key_signs() {
        if !have(&["softhsm2-util", "pkcs11-tool", "openssl", "xmlsec1"]) {
            return;
        }
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let t = TestToken::new(false);
        t.add_key("02", "signing", "client.key.der", "client.der");
        let token = Token::open(Path::new(&softhsm_module()), &Selection::default(), || {
            Ok(PIN.to_string())
        })
        .unwrap();
        verify(t.dir.path(), &signed_dps(&token));
    }
}
