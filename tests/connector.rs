//! The connector against a local HTTPS server that requires a client
//! certificate, with the client key on a SoftHSM token.

mod common;

use common::*;
use nfse::connector::{Connector, Endpoints, SubmitError, gunzip_b64, gzip_b64};
use nfse::pkcs11::{Selection, Token};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

fn connector(t: &TestToken, base: &str) -> Connector {
    let token = Token::open(Path::new(&softhsm_module()), &Selection::default(), || {
        Ok(PIN.into())
    })
    .unwrap();
    let tls = nfse::tls::connector(Arc::new(token), Some(&t.path("ca.pem"))).unwrap();
    let mut c = Connector::new(
        tls,
        Endpoints {
            sefin: format!("{base}/SefinNacional"),
            adn: base.to_string(),
        },
    );
    c.recovery_delays = vec![Duration::from_millis(10)];
    c
}

fn ok_body(xml: &str) -> String {
    format!(
        r#"{{"chaveAcesso":"3106200","nfseXmlGZipB64":"{}"}}"#,
        gzip_b64(xml.as_bytes())
    )
}

fn ready() -> Option<std::sync::MutexGuard<'static, ()>> {
    if !have(&["softhsm2-util", "pkcs11-tool", "openssl"]) {
        eprintln!("skipped: SoftHSM, OpenSC tools or openssl not installed");
        return None;
    }
    Some(LOCK.lock().unwrap_or_else(|e| e.into_inner()))
}

#[test]
fn submits_over_tls12_when_the_server_renegotiates_for_the_certificate() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, seen) = serve(
        &t,
        Box::new(|method, path, body| {
            assert_eq!((method, path), ("POST", "/SefinNacional/nfse"));
            let v: serde_json::Value = serde_json::from_str(body).unwrap();
            let dps = gunzip_b64(v["dpsXmlGZipB64"].as_str().unwrap()).unwrap();
            assert_eq!(dps, b"<DPS>signed</DPS>");
            (201, "application/json".into(), ok_body("<NFSe>ok</NFSe>"))
        }),
    );
    let issued = connector(&t, &base)
        .submit_dps("<DPS>signed</DPS>", "DPS1")
        .unwrap();
    assert_eq!(issued.nfse_xml, "<NFSe>ok</NFSe>");
    assert_eq!(issued.chave_acesso, "3106200");
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.authenticated, 1,
        "client certificate presented and verified"
    );
    assert_eq!(seen.versions, ["TLSv1.2"]);
}

#[test]
fn rejection_lists_the_errors_without_retrying() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, seen) = serve(
        &t,
        Box::new(|_, _, _| {
            (
                400,
                "application/json".into(),
                r#"{"erros":[{"codigo":"E0004","descricao":"Id"}]}"#.into(),
            )
        }),
    );
    match connector(&t, &base).submit_dps("<DPS/>", "DPS1") {
        Err(SubmitError::Rejected(e)) => assert_eq!(e, ["E0004 - Id"]),
        other => panic!("{other:?}"),
    }
    assert_eq!(seen.lock().unwrap().requests, ["POST /SefinNacional/nfse"]);
}

#[test]
fn server_error_is_recovered_by_looking_up_the_dps_id() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, seen) = serve(
        &t,
        Box::new(|method, path, _| match (method, path) {
            ("POST", _) => (502, "text/plain".into(), "bad gateway".into()),
            ("GET", "/SefinNacional/dps/DPS1") => (
                200,
                "application/json".into(),
                r#"{"idDps":"DPS1","chaveAcesso":"K1"}"#.into(),
            ),
            ("GET", "/SefinNacional/nfse/K1") => {
                (200, "application/json".into(), ok_body("<NFSe>K1</NFSe>"))
            }
            _ => (404, "text/plain".into(), String::new()),
        }),
    );
    let issued = connector(&t, &base).submit_dps("<DPS/>", "DPS1").unwrap();
    assert_eq!(issued.nfse_xml, "<NFSe>K1</NFSe>");
    assert_eq!(
        seen.lock().unwrap().requests,
        [
            "POST /SefinNacional/nfse",
            "GET /SefinNacional/dps/DPS1",
            "GET /SefinNacional/nfse/K1"
        ]
    );
}

#[test]
fn unknown_outcome_resends_the_same_payload_once() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, seen) = serve(
        &t,
        Box::new(|_, _, _| (503, "text/plain".into(), "down".into())),
    );
    match connector(&t, &base).submit_dps("<DPS/>", "DPS1") {
        Err(SubmitError::Unknown(_)) => {}
        other => panic!("{other:?}"),
    }
    let requests = seen.lock().unwrap().requests.clone();
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST")).count(),
        2,
        "{requests:?}"
    );
}

#[test]
fn fetches_the_danfse_pdf() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, _) = serve(
        &t,
        Box::new(|_, path, _| {
            assert_eq!(path, "/danfse/K1");
            (200, "application/pdf".into(), "%PDF-1.4 x".into())
        }),
    );
    assert_eq!(
        connector(&t, &base).fetch_danfe("K1").unwrap(),
        b"%PDF-1.4 x"
    );
}

#[test]
fn submits_when_the_certificate_is_asked_in_the_first_handshake() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, seen) = serve_with(
        &t,
        ClientAuth::Initial,
        Box::new(|_, _, _| (201, "application/json".into(), ok_body("<NFSe/>"))),
    );
    connector(&t, &base).submit_dps("<DPS/>", "DPS1").unwrap();
    assert_eq!(seen.lock().unwrap().authenticated, 1);
}

#[test]
fn token_with_always_authenticate_key_works_through_renegotiation() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(true);
    let (base, seen) = serve(
        &t,
        Box::new(|_, _, _| (201, "application/json".into(), ok_body("<NFSe/>"))),
    );
    connector(&t, &base).submit_dps("<DPS/>", "DPS1").unwrap();
    assert_eq!(seen.lock().unwrap().authenticated, 1);
}
