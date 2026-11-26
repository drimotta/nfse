//! The C API, called the way a C program calls it: JSON strings in, a JSON
//! string and a status code out.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use common::*;
use nfse::capi::*;
use serde_json::{Value, json};
use std::ffi::{CStr, CString, c_char};
use std::process::Command;
use std::ptr;
use std::sync::Mutex;

// SOFTHSM2_CONF is process-wide, so the token tests run one at a time.
static LOCK: Mutex<()> = Mutex::new(());

const NOV: &str = include_str!("fixtures/nfse-ibscbs.xml");

fn ready() -> Option<std::sync::MutexGuard<'static, ()>> {
    if !have(&["softhsm2-util", "pkcs11-tool", "openssl", "xmlsec1"]) {
        eprintln!("skipped: SoftHSM, OpenSC tools, openssl or xmlsec1 not installed");
        return None;
    }
    Some(LOCK.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Takes the response the library allocated and frees it.
fn take(response: *mut c_char) -> Value {
    assert!(!response.is_null(), "no response");
    let text = unsafe { CStr::from_ptr(response) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { nfse_free(response) };
    serde_json::from_str(&text).unwrap()
}

fn call(
    f: unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> i32,
    req: &Value,
) -> (i32, Value) {
    let req = CString::new(req.to_string()).unwrap();
    let mut out = ptr::null_mut();
    let code = unsafe { f(req.as_ptr(), &mut out) };
    (code, take(out))
}

type SessionFn = unsafe extern "C" fn(*mut NfseSession, *const c_char, *mut *mut c_char) -> i32;

fn call_session(f: SessionFn, s: *mut NfseSession, req: &Value) -> (i32, Value) {
    let req = CString::new(req.to_string()).unwrap();
    let mut out = ptr::null_mut();
    let code = unsafe { f(s, req.as_ptr(), &mut out) };
    (code, take(out))
}

fn open(req: &Value) -> (i32, *mut NfseSession, Value) {
    let req = CString::new(req.to_string()).unwrap();
    let mut out = ptr::null_mut();
    let mut session = ptr::null_mut();
    let code = unsafe { nfse_session_open(req.as_ptr(), &mut session, &mut out) };
    (code, session, take(out))
}

fn content() -> Value {
    let map = nfse::input::infdps_from_xml(NOV).unwrap();
    let mut map = nfse::input::combine(
        Some(map),
        &Default::default(),
        nfse::dps::Environment::Staging,
    )
    .unwrap();
    for f in nfse::input::GENERATED {
        map.remove(f);
    }
    Value::Object(map)
}

fn build_request() -> Value {
    json!({
        "environment": "staging",
        "serie": "1",
        "n_dps": "42",
        "emitted_at": "2026-11-26T10:05:09-03:00",
        "content": content(),
    })
}

fn unsigned_dps() -> (String, String) {
    let (code, resp) = call(nfse_build_dps, &build_request());
    assert_eq!(code, NFSE_OK, "{resp}");
    (
        resp["id"].as_str().unwrap().to_string(),
        resp["xml"].as_str().unwrap().to_string(),
    )
}

fn session_request() -> Value {
    json!({"module": softhsm_module(), "pin": PIN})
}

#[test]
fn version_is_the_crate_version() {
    let v = unsafe { CStr::from_ptr(nfse_version()) }.to_str().unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}

#[test]
fn build_uses_the_given_numbers_and_time() {
    let (code, resp) = call(nfse_build_dps, &build_request());
    assert_eq!(code, NFSE_OK, "{resp}");
    assert_eq!(resp["id"], "DPS310620021234567800019500001000000000000042");
    let xml = resp["xml"].as_str().unwrap();
    assert!(xml.contains("<serie>1</serie><nDPS>42</nDPS>"));
    assert!(xml.contains("<dhEmi>2026-11-26T10:05:09-03:00</dhEmi>"));
    assert!(xml.contains("<tpAmb>2</tpAmb>"));
}

#[test]
fn build_reuses_an_earlier_document_with_overrides() {
    let req = json!({
        "environment": "production",
        "serie": "1",
        "n_dps": "7",
        "emitted_at": "2026-11-26T10:05:09-03:00",
        "reuse_xml": NOV,
        "content": {"dCompet": "2026-11-01"},
    });
    let (code, resp) = call(nfse_build_dps, &req);
    assert_eq!(code, NFSE_OK, "{resp}");
    let xml = resp["xml"].as_str().unwrap();
    assert!(xml.contains("<dCompet>2026-11-01</dCompet>"), "{xml}");
    assert!(xml.contains("<tpAmb>1</tpAmb>"));
}

#[test]
fn build_errors_are_input_errors_with_a_message() {
    let cases = [
        json!({"environment": "staging", "serie": "1", "n_dps": "1", "content": {}}),
        json!({"environment": "elsewhere", "serie": "1", "n_dps": "1", "content": content()}),
        json!({"environment": "staging", "serie": "1", "n_dps": "01", "content": content()}),
        json!({"environment": "staging", "content": content()}),
        json!({"environment": "staging", "serie": "1", "n_dps": "1", "emitted_at": "yesterday", "content": content()}),
        json!([1, 2]),
    ];
    for req in cases {
        let (code, resp) = call(nfse_build_dps, &req);
        assert_eq!(code, NFSE_ERR_INPUT, "{req} -> {resp}");
        assert_eq!(resp["error"]["code"], "input");
        assert!(!resp["error"]["message"].as_str().unwrap().is_empty());
    }
}

#[test]
fn bad_pointers_and_text_do_not_crash() {
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { nfse_build_dps(ptr::null(), &mut out) },
        NFSE_ERR_INPUT
    );
    assert_eq!(take(out)["error"]["code"], "input");
    let bad = [0xffu8, 0xfe, 0];
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { nfse_build_dps(bad.as_ptr() as *const c_char, &mut out) },
        NFSE_ERR_INPUT
    );
    take(out);
    let req = CString::new("{}").unwrap();
    assert_eq!(
        unsafe { nfse_build_dps(req.as_ptr(), ptr::null_mut()) },
        NFSE_ERR_INPUT
    );
    let mut out = ptr::null_mut();
    assert_eq!(
        unsafe { nfse_sign_dps(ptr::null_mut(), req.as_ptr(), &mut out) },
        NFSE_ERR_INPUT
    );
    take(out);
    unsafe {
        nfse_free(ptr::null_mut());
        nfse_session_close(ptr::null_mut());
    }
}

#[test]
fn lists_certificates_without_a_pin() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (code, resp) = call(nfse_list_certificates, &json!({"module": softhsm_module()}));
    assert_eq!(code, NFSE_OK, "{resp}");
    let tokens = resp["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 1, "{resp}");
    assert_eq!(tokens[0]["label"], "A3-TEST");
    let certs = tokens[0]["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 1, "{resp}");
    assert_eq!(certs[0]["id"], "01");
    assert_eq!(certs[0]["label"], "signing");
    assert_eq!(certs[0]["usable"], true);
    assert!(
        certs[0]["subject"]
            .as_str()
            .unwrap()
            .contains("EMPRESA TESTE:12345678000195")
    );
    assert!(certs[0]["not_after"].as_str().unwrap().starts_with("20"));
    let der = B64.decode(certs[0]["der_b64"].as_str().unwrap()).unwrap();
    assert_eq!(der, t.der("client.pem"));
}

#[test]
fn a_missing_module_is_a_token_error() {
    let (code, resp) = call(
        nfse_list_certificates,
        &json!({"module": "/nonexistent.so"}),
    );
    assert_eq!(code, NFSE_ERR_TOKEN, "{resp}");
    let (code, s, resp) = open(&json!({"module": "/nonexistent.so", "pin": "1"}));
    assert_eq!(code, NFSE_ERR_TOKEN, "{resp}");
    assert!(s.is_null());
}

#[test]
fn a_wrong_pin_is_reported_as_such() {
    let Some(_g) = ready() else { return };
    let _t = TestToken::new(false);
    let (code, s, resp) = open(&json!({"module": softhsm_module(), "pin": "0000"}));
    assert_eq!(code, NFSE_ERR_PIN, "{resp}");
    assert_eq!(resp["error"]["code"], "pin");
    assert!(s.is_null());
}

#[test]
fn signs_a_dps_that_xmlsec_verifies() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (id, xml) = unsigned_dps();
    let (code, s, resp) = open(&session_request());
    assert_eq!(code, NFSE_OK, "{resp}");
    assert_eq!(resp["certificate_b64"], B64.encode(t.der("client.pem")));
    let (code, resp) = call_session(nfse_sign_dps, s, &json!({"xml": xml}));
    unsafe { nfse_session_close(s) };
    assert_eq!(code, NFSE_OK, "{resp}");
    assert_eq!(resp["id"], id.as_str());
    let signed = resp["xml"].as_str().unwrap();
    let file = t.path("signed.xml");
    std::fs::write(&file, signed).unwrap();
    let out = Command::new("xmlsec1")
        .args(["--verify", "--trusted-pem"])
        .arg(t.path("ca.pem"))
        .args(["--id-attr:Id", "infDPS"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn refuses_to_sign_anything_but_an_unsigned_dps() {
    let Some(_g) = ready() else { return };
    let _t = TestToken::new(false);
    let (_, xml) = unsigned_dps();
    let (code, s, resp) = open(&session_request());
    assert_eq!(code, NFSE_OK, "{resp}");
    let tampered = xml.replace("</infDPS>", "<x></x></infDPS>");
    let (code, resp) = call_session(nfse_sign_dps, s, &json!({"xml": tampered}));
    unsafe { nfse_session_close(s) };
    assert_eq!(code, NFSE_ERR_INPUT, "{resp}");
}

fn verify_challenge(t: &TestToken, resp: &Value, challenge: &[u8]) {
    let mut signed = b"NFSE-LOGIN-V1\n".to_vec();
    signed.extend_from_slice(challenge);
    std::fs::write(t.path("challenge.bin"), &signed).unwrap();
    let sig = B64.decode(resp["signature_b64"].as_str().unwrap()).unwrap();
    std::fs::write(t.path("challenge.sig"), sig).unwrap();
    run(
        t.dir.path(),
        "openssl",
        &[
            "x509",
            "-in",
            "client.pem",
            "-pubkey",
            "-noout",
            "-out",
            "client.pub",
        ],
    );
    let out = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            "client.pub",
            "-signature",
            "challenge.sig",
            "challenge.bin",
        ])
        .current_dir(t.dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn signs_a_login_challenge_under_its_own_prefix() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (code, s, resp) = open(&session_request());
    assert_eq!(code, NFSE_OK, "{resp}");
    let challenge = [7u8; 32];
    let (code, resp) = call_session(
        nfse_sign_challenge,
        s,
        &json!({"challenge_b64": B64.encode(challenge)}),
    );
    assert_eq!(code, NFSE_OK, "{resp}");
    assert_eq!(resp["algorithm"], "rsa-pkcs1-sha256");
    assert_eq!(resp["prefix"], "NFSE-LOGIN-V1\n");
    assert_eq!(resp["certificate_b64"], B64.encode(t.der("client.pem")));
    verify_challenge(&t, &resp, &challenge);

    for bad in [
        json!({"challenge_b64": B64.encode([1u8; 15])}),
        json!({"challenge_b64": B64.encode([1u8; 1025])}),
        json!({"challenge_b64": "not base64!"}),
        json!({}),
    ] {
        let (code, resp) = call_session(nfse_sign_challenge, s, &bad);
        assert_eq!(code, NFSE_ERR_INPUT, "{bad} -> {resp}");
    }
    unsafe { nfse_session_close(s) };
}

fn submit_request(t: &TestToken, base: &str, xml: &str, id: &str) -> Value {
    json!({
        "environment": "staging",
        "signed_xml": xml,
        "dps_id": id,
        "sefin_url": format!("{base}/SefinNacional"),
        "adn_url": base,
        "ca_bundle": t.path("ca.pem").to_str().unwrap(),
        "recovery_delays_ms": [10],
    })
}

#[test]
fn submits_and_reports_the_issued_nfse() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, seen) = serve(
        &t,
        Box::new(|method, path, _| match (method, path) {
            ("POST", "/SefinNacional/nfse") => (
                201,
                "application/json".into(),
                format!(
                    r#"{{"chaveAcesso":"K1","nfseXmlGZipB64":"{}"}}"#,
                    nfse::connector::gzip_b64(b"<NFSe>ok</NFSe>")
                ),
            ),
            _ => (404, "text/plain".into(), String::new()),
        }),
    );
    let (code, s, resp) = open(&session_request());
    assert_eq!(code, NFSE_OK, "{resp}");
    let (code, resp) = call_session(
        nfse_submit,
        s,
        &submit_request(&t, &base, "<DPS>signed</DPS>", "DPS1"),
    );
    unsafe { nfse_session_close(s) };
    assert_eq!(code, NFSE_OK, "{resp}");
    assert_eq!(resp["chave_acesso"], "K1");
    assert_eq!(resp["nfse_xml"], "<NFSe>ok</NFSe>");
    assert_eq!(seen.lock().unwrap().authenticated, 1);
}

#[test]
fn a_rejection_carries_the_rfb_messages() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, _) = serve(
        &t,
        Box::new(|_, _, _| {
            (
                400,
                "application/json".into(),
                r#"{"erros":[{"codigo":"E0004","descricao":"Id"}]}"#.into(),
            )
        }),
    );
    let (_, s, _) = open(&session_request());
    let (code, resp) = call_session(nfse_submit, s, &submit_request(&t, &base, "<DPS/>", "DPS1"));
    unsafe { nfse_session_close(s) };
    assert_eq!(code, NFSE_ERR_REJECTED, "{resp}");
    assert_eq!(resp["error"]["code"], "rejected");
    assert_eq!(resp["messages"], json!(["E0004 - Id"]));
}

#[test]
fn an_unknown_outcome_is_its_own_code() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, _) = serve(
        &t,
        Box::new(|_, _, _| (503, "text/plain".into(), "down".into())),
    );
    let (_, s, _) = open(&session_request());
    let (code, resp) = call_session(nfse_submit, s, &submit_request(&t, &base, "<DPS/>", "DPS1"));
    unsafe { nfse_session_close(s) };
    assert_eq!(code, NFSE_ERR_UNKNOWN_OUTCOME, "{resp}");
    assert_eq!(resp["error"]["code"], "unknown_outcome");
}

#[test]
fn fetches_the_danfe() {
    let Some(_g) = ready() else { return };
    let t = TestToken::new(false);
    let (base, seen) = serve(
        &t,
        Box::new(|method, path, _| match (method, path) {
            ("GET", "/danfse/K1") => (200, "application/pdf".into(), "%PDF-1.4".into()),
            _ => (404, "text/plain".into(), String::new()),
        }),
    );
    let (_, s, _) = open(&session_request());
    let mut req = submit_request(&t, &base, "", "");
    req["chave_acesso"] = json!("K1");
    let (code, resp) = call_session(nfse_fetch_danfe, s, &req);
    unsafe { nfse_session_close(s) };
    assert_eq!(code, NFSE_OK, "{resp} {:?}", seen.lock().unwrap().requests);
    assert_eq!(
        B64.decode(resp["pdf_b64"].as_str().unwrap()).unwrap(),
        b"%PDF-1.4"
    );
}
