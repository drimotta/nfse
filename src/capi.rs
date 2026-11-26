//! The C API declared in `include/nfse.h`: JSON requests in, a JSON response
//! and a status code out. The server builds DPS documents with it; the agent
//! on the user's machine signs and submits them with the token.

use crate::connector::{Connector, Endpoints, SubmitError};
use crate::dps::{self, Dps, Environment, SHA256_PREFIX, Signer, brt, digest_info};
use crate::input;
use crate::pkcs11::{self, CertInfo, Selection, Token};
use crate::tls;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const NFSE_OK: i32 = 0;
pub const NFSE_ERR_INPUT: i32 = 1;
pub const NFSE_ERR_TOKEN: i32 = 2;
pub const NFSE_ERR_PIN: i32 = 3;
pub const NFSE_ERR_PIN_LOCKED: i32 = 4;
pub const NFSE_ERR_REJECTED: i32 = 5;
pub const NFSE_ERR_UNKNOWN_OUTCOME: i32 = 6;
pub const NFSE_ERR_NETWORK: i32 = 7;
pub const NFSE_ERR_INTERNAL: i32 = 99;

/// The prefix of every signed login challenge. A DPS signature covers an XML
/// `SignedInfo`, which can never start with it.
pub const CHALLENGE_PREFIX: &str = "NFSE-LOGIN-V1\n";
const CHALLENGE_SIZES: std::ops::RangeInclusive<usize> = 16..=1024;

/// A logged-in token session (`nfse_session` in C).
pub struct NfseSession {
    token: Arc<Token>,
}

enum Fail {
    Input(String),
    Token(anyhow::Error),
    Rejected(Vec<String>),
    Unknown(String),
    Network(String),
    Internal(String),
}

type Outcome = Result<Value, Fail>;

fn input_error(e: impl std::fmt::Display) -> Fail {
    Fail::Input(e.to_string())
}

impl Fail {
    fn code(&self) -> i32 {
        match self {
            Fail::Input(_) => NFSE_ERR_INPUT,
            Fail::Token(e) => match pin_problem(e) {
                Some(true) => NFSE_ERR_PIN_LOCKED,
                Some(false) => NFSE_ERR_PIN,
                None => NFSE_ERR_TOKEN,
            },
            Fail::Rejected(_) => NFSE_ERR_REJECTED,
            Fail::Unknown(_) => NFSE_ERR_UNKNOWN_OUTCOME,
            Fail::Network(_) => NFSE_ERR_NETWORK,
            Fail::Internal(_) => NFSE_ERR_INTERNAL,
        }
    }

    fn body(&self) -> Value {
        let name = match self.code() {
            NFSE_ERR_INPUT => "input",
            NFSE_ERR_TOKEN => "token",
            NFSE_ERR_PIN => "pin",
            NFSE_ERR_PIN_LOCKED => "pin_locked",
            NFSE_ERR_REJECTED => "rejected",
            NFSE_ERR_UNKNOWN_OUTCOME => "unknown_outcome",
            NFSE_ERR_NETWORK => "network",
            _ => "internal",
        };
        let message = match self {
            Fail::Input(m) | Fail::Unknown(m) | Fail::Network(m) | Fail::Internal(m) => m.clone(),
            Fail::Token(e) => format!("{e:#}"),
            Fail::Rejected(m) => format!("DPS rejected: {}", m.join("; ")),
        };
        let mut body = json!({"error": {"code": name, "message": message}});
        if let Fail::Rejected(messages) = self {
            body["messages"] = json!(messages);
        }
        body
    }
}

/// `Some(locked)` when the token refused the PIN.
fn pin_problem(e: &anyhow::Error) -> Option<bool> {
    use cryptoki::error::{Error, RvError};
    e.chain()
        .find_map(|cause| match cause.downcast_ref::<Error>() {
            Some(Error::Pkcs11(RvError::PinLocked, _)) => Some(true),
            Some(Error::Pkcs11(
                RvError::PinIncorrect | RvError::PinInvalid | RvError::PinLenRange,
                _,
            )) => Some(false),
            _ => None,
        })
}

/// Runs `f` on the parsed request and writes the response. Panics never
/// cross into C.
fn respond(
    request: *const c_char,
    response: *mut *mut c_char,
    f: impl FnOnce(Map<String, Value>) -> Outcome,
) -> i32 {
    if response.is_null() {
        return NFSE_ERR_INPUT;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let request = parse_request(request)?;
        f(request)
    }))
    .unwrap_or_else(|_| Err(Fail::Internal("panic in nfse".into())));
    let (code, body) = match outcome {
        Ok(body) => (NFSE_OK, body),
        Err(fail) => (fail.code(), fail.body()),
    };
    let text = CString::new(body.to_string()).unwrap_or_else(|_| c"{}".to_owned());
    // SAFETY: checked non-null above; the caller owns the slot.
    unsafe { *response = text.into_raw() };
    code
}

fn parse_request(request: *const c_char) -> Result<Map<String, Value>, Fail> {
    if request.is_null() {
        return Err(input_error("no request"));
    }
    // SAFETY: the caller passes a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(request) }
        .to_str()
        .map_err(|_| input_error("the request is not UTF-8"))?;
    match serde_json::from_str(text).map_err(|e| input_error(format!("bad JSON: {e}")))? {
        Value::Object(map) => Ok(map),
        _ => Err(input_error("the request must be a JSON object")),
    }
}

fn text<'a>(req: &'a Map<String, Value>, field: &str) -> Result<&'a str, Fail> {
    optional_text(req, field)?.ok_or_else(|| input_error(format!("{field} is required")))
}

fn optional_text<'a>(req: &'a Map<String, Value>, field: &str) -> Result<Option<&'a str>, Fail> {
    match req.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(input_error(format!("{field} must be a string"))),
    }
}

fn environment(req: &Map<String, Value>) -> Result<Environment, Fail> {
    match text(req, "environment")? {
        "staging" => Ok(Environment::Staging),
        "production" => Ok(Environment::Production),
        other => Err(input_error(format!(
            "environment must be \"staging\" or \"production\", got {other:?}"
        ))),
    }
}

fn session<'a>(session: *mut NfseSession) -> Result<&'a NfseSession, Fail> {
    // SAFETY: a pointer from nfse_session_open, not yet closed.
    unsafe { session.as_ref() }.ok_or_else(|| input_error("no session"))
}

#[unsafe(no_mangle)]
pub extern "C" fn nfse_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// # Safety
/// `request` is NULL or a NUL-terminated string; `response` is NULL or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_build_dps(request: *const c_char, response: *mut *mut c_char) -> i32 {
    respond(request, response, build)
}

fn build(req: Map<String, Value>) -> Outcome {
    let env = environment(&req)?;
    let serie = text(&req, "serie")?;
    let n_dps = text(&req, "n_dps")?;
    let now = match optional_text(&req, "emitted_at")? {
        Some(t) => {
            DateTime::parse_from_rfc3339(t).map_err(|e| input_error(format!("emitted_at: {e}")))?
        }
        None => Utc::now().with_timezone(&brt()),
    };
    let reused = match optional_text(&req, "reuse_xml")? {
        Some(xml) => Some(
            input::infdps_from_xml(xml).map_err(|e| input_error(format!("reuse_xml: {e:#}")))?,
        ),
        None => None,
    };
    let overrides = match req.get("content") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err(input_error("content must be an object")),
    };
    let content =
        input::combine(reused, &overrides, env).map_err(|e| input_error(format!("{e:#}")))?;
    let dps = dps::build_dps_numbered(&content, env, now, serie, n_dps)
        .map_err(|e| input_error(format!("{e:#}")))?;
    Ok(json!({"id": dps.id, "xml": dps.xml()}))
}

/// # Safety
/// As [`nfse_build_dps`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_list_certificates(
    request: *const c_char,
    response: *mut *mut c_char,
) -> i32 {
    respond(request, response, |req| {
        let module = text(&req, "module")?;
        let tokens = pkcs11::list_certificates(Path::new(module)).map_err(Fail::Token)?;
        let tokens: Vec<Value> = tokens
            .into_iter()
            .map(|t| {
                let certificates: Vec<Value> = t
                    .certificates
                    .iter()
                    .map(|c| {
                        let info = CertInfo::parse(&c.der).ok();
                        let not_after = x509_parser::parse_x509_certificate(&c.der)
                            .ok()
                            .and_then(|(_, cert)| {
                                DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
                            })
                            .map(|d| d.to_rfc3339());
                        json!({
                            "id": hex::encode(&c.id),
                            "label": c.label,
                            "der_b64": B64.encode(&c.der),
                            "subject": info.as_ref().map(|i| i.subject.clone()),
                            "not_after": not_after,
                            "usable": info.as_ref().is_some_and(|i| i.usable()),
                        })
                    })
                    .collect();
                json!({"label": t.label, "serial": t.serial, "certificates": certificates})
            })
            .collect();
        Ok(json!({ "tokens": tokens }))
    })
}

/// # Safety
/// As [`nfse_build_dps`]; `session` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_session_open(
    request: *const c_char,
    session: *mut *mut NfseSession,
    response: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        return respond(request, response, |_| {
            Err(input_error("no session pointer"))
        });
    }
    // SAFETY: checked non-null.
    unsafe { *session = std::ptr::null_mut() };
    respond(request, response, |req| {
        let module = text(&req, "module")?;
        let pin = text(&req, "pin")?.to_string();
        let selection = Selection {
            token_label: optional_text(&req, "token_label")?.map(str::to_string),
            key_label: optional_text(&req, "key_label")?.map(str::to_string),
            key_id: optional_text(&req, "key_id")?.map(str::to_string),
        };
        let token =
            Token::open(Path::new(module), &selection, move || Ok(pin)).map_err(Fail::Token)?;
        let certificate = B64.encode(token.certificate());
        let handle = Box::new(NfseSession {
            token: Arc::new(token),
        });
        // SAFETY: checked non-null.
        unsafe { *session = Box::into_raw(handle) };
        Ok(json!({ "certificate_b64": certificate }))
    })
}

/// # Safety
/// `session` is NULL or from [`nfse_session_open`]; the rest as
/// [`nfse_build_dps`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_sign_dps(
    s: *mut NfseSession,
    request: *const c_char,
    response: *mut *mut c_char,
) -> i32 {
    respond(request, response, |req| {
        let s = session(s)?;
        let dps = Dps::from_unsigned_xml(text(&req, "xml")?)
            .map_err(|e| input_error(format!("{e:#}")))?;
        let signed = dps::sign_dps(&dps, s.token.as_ref()).map_err(Fail::Token)?;
        Ok(json!({"id": dps.id, "xml": signed}))
    })
}

/// # Safety
/// As [`nfse_sign_dps`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_sign_challenge(
    s: *mut NfseSession,
    request: *const c_char,
    response: *mut *mut c_char,
) -> i32 {
    respond(request, response, |req| {
        let s = session(s)?;
        let challenge = B64
            .decode(text(&req, "challenge_b64")?)
            .map_err(|e| input_error(format!("challenge_b64: {e}")))?;
        if !CHALLENGE_SIZES.contains(&challenge.len()) {
            return Err(input_error(format!(
                "the challenge must have {} to {} bytes",
                CHALLENGE_SIZES.start(),
                CHALLENGE_SIZES.end()
            )));
        }
        let mut signed = CHALLENGE_PREFIX.as_bytes().to_vec();
        signed.extend_from_slice(&challenge);
        let info = digest_info(&SHA256_PREFIX, &Sha256::digest(&signed));
        let signature = s.token.sign_digest_info(&info).map_err(Fail::Token)?;
        Ok(json!({
            "signature_b64": B64.encode(signature),
            "certificate_b64": B64.encode(s.token.certificate()),
            "algorithm": "rsa-pkcs1-sha256",
            "prefix": CHALLENGE_PREFIX,
        }))
    })
}

fn connector(s: &NfseSession, req: &Map<String, Value>) -> Result<Connector, Fail> {
    let defaults = Endpoints::for_env(environment(req)?);
    let endpoints = Endpoints {
        sefin: optional_text(req, "sefin_url")?
            .map(str::to_string)
            .unwrap_or(defaults.sefin),
        adn: optional_text(req, "adn_url")?
            .map(str::to_string)
            .unwrap_or(defaults.adn),
    };
    let ca_bundle = optional_text(req, "ca_bundle")?.map(Path::new);
    let signer: tls::SharedSigner = s.token.clone();
    let tls = tls::connector(signer, ca_bundle).map_err(Fail::Token)?;
    let mut connector = Connector::new(tls, endpoints);
    match req.get("recovery_delays_ms") {
        None | Some(Value::Null) => {}
        Some(Value::Array(ms)) => {
            connector.recovery_delays = ms
                .iter()
                .map(|v| v.as_u64().map(Duration::from_millis))
                .collect::<Option<_>>()
                .ok_or_else(|| input_error("recovery_delays_ms must hold whole numbers"))?;
        }
        Some(_) => return Err(input_error("recovery_delays_ms must be an array")),
    }
    Ok(connector)
}

/// # Safety
/// As [`nfse_sign_dps`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_submit(
    s: *mut NfseSession,
    request: *const c_char,
    response: *mut *mut c_char,
) -> i32 {
    respond(request, response, |req| {
        let s = session(s)?;
        let signed = text(&req, "signed_xml")?;
        let dps_id = text(&req, "dps_id")?;
        let connector = connector(s, &req)?;
        match connector.submit_dps(signed, dps_id) {
            Ok(issued) => Ok(json!({
                "chave_acesso": issued.chave_acesso,
                "nfse_xml": issued.nfse_xml,
            })),
            Err(SubmitError::Rejected(messages)) => Err(Fail::Rejected(messages)),
            Err(SubmitError::Unknown(why)) => Err(Fail::Unknown(format!(
                "outcome unknown ({why}); look the DPS id up before sending it again"
            ))),
        }
    })
}

/// # Safety
/// As [`nfse_sign_dps`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_fetch_danfe(
    s: *mut NfseSession,
    request: *const c_char,
    response: *mut *mut c_char,
) -> i32 {
    respond(request, response, |req| {
        let s = session(s)?;
        let chave = text(&req, "chave_acesso")?;
        let pdf = connector(s, &req)?
            .fetch_danfe(chave)
            .map_err(|e| Fail::Network(format!("{e:#}")))?;
        Ok(json!({ "pdf_b64": B64.encode(pdf) }))
    })
}

/// # Safety
/// `session` is NULL or from [`nfse_session_open`], and is not used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_session_close(session: *mut NfseSession) {
    if !session.is_null() {
        // SAFETY: from Box::into_raw in nfse_session_open.
        drop(unsafe { Box::from_raw(session) });
    }
}

/// # Safety
/// `response` is NULL or a response from this library, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nfse_free(response: *mut c_char) {
    if !response.is_null() {
        // SAFETY: from CString::into_raw in respond.
        drop(unsafe { CString::from_raw(response) });
    }
}
