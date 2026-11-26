//! The signing key on a PKCS#11 token (OpenSC for the A3 card, SoftHSM in
//! tests).

use crate::dps::Signer;
use anyhow::{Context, Result, anyhow, bail};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Where to find the PKCS#11 module when `NFSE_PKCS11_MODULE` is not set, in
/// order. Homebrew on Apple Silicon and Intel, the OpenSC installer; Debian
/// and Ubuntu multiarch, Fedora, then plain prefixes.
pub fn module_candidates(os: &str) -> Vec<PathBuf> {
    let paths: &[&str] = match os {
        "macos" => &[
            "/opt/homebrew/lib/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
            "/Library/OpenSC/lib/opensc-pkcs11.so",
        ],
        _ => &[
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib64/opensc-pkcs11.so",
            "/usr/lib/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
        ],
    };
    paths.iter().map(PathBuf::from).collect()
}

/// The module to load: the override if given, else the first candidate that
/// exists.
pub fn resolve_module(
    overridden: Option<&str>,
    os: &str,
    exists: impl Fn(&Path) -> bool,
) -> Result<PathBuf> {
    if let Some(path) = overridden {
        return Ok(PathBuf::from(path));
    }
    let candidates = module_candidates(os);
    candidates
        .iter()
        .find(|p| exists(p))
        .cloned()
        .ok_or_else(|| {
            let list: Vec<String> = candidates.iter().map(|p| p.display().to_string()).collect();
            anyhow!(
                "OpenSC PKCS#11 module not found; set NFSE_PKCS11_MODULE. Searched: {}",
                list.join(", ")
            )
        })
}

/// How to pick the token and key when there is more than one.
#[derive(Debug, Default, Clone)]
pub struct Selection {
    pub token_label: Option<String>,
    pub key_label: Option<String>,
    /// CKA_ID of the key, hex.
    pub key_id: Option<String>,
}

type CSign = unsafe extern "C" fn(
    cryptoki_sys::CK_SESSION_HANDLE,
    *mut u8,
    cryptoki_sys::CK_ULONG,
    *mut u8,
    *mut cryptoki_sys::CK_ULONG,
) -> cryptoki_sys::CK_RV;

pub struct Token {
    session: Mutex<Session>,
    key: ObjectHandle,
    certificate: Vec<u8>,
    /// Set when the key has CKA_ALWAYS_AUTHENTICATE: the PIN is given again
    /// before every signature.
    always_auth: Option<(AuthPin, libloading::Library)>,
    // Keep the context alive (and finalized last).
    _ctx: Module,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("always_auth", &self.always_auth.is_some())
            .finish()
    }
}

impl Token {
    /// Loads the module, picks the token, logs in and finds the key and its
    /// certificate. `pin` is asked only once a token was found.
    pub fn open(
        module: &Path,
        selection: &Selection,
        pin: impl FnOnce() -> Result<String>,
    ) -> Result<Token> {
        let ctx = Module::open(module)?;
        let slot = pick_slot(&ctx, selection)?;
        let session = ctx
            .open_ro_session(slot)
            .context("cannot open a session on the token")?;
        let pin = AuthPin::from(pin()?);
        session
            .login(UserType::User, Some(&pin))
            .context("login failed (wrong PIN?)")?;

        let (key, id) = pick_key(&session, selection)?;
        let certificate = find_certificate(&session, &id)?;
        let always_auth = match session
            .get_attributes(key, &[AttributeType::AlwaysAuthenticate])?
            .first()
        {
            Some(Attribute::AlwaysAuthenticate(true)) => {
                // SAFETY: the module is already loaded by cryptoki; this only
                // takes another reference to it to call C_Sign directly.
                let lib = unsafe { libloading::Library::new(module) }
                    .context("cannot reload the PKCS#11 module")?;
                Some((pin, lib))
            }
            _ => None,
        };
        Ok(Token {
            session: Mutex::new(session),
            key,
            certificate,
            always_auth,
            _ctx: ctx,
        })
    }
}

fn pick_slot(ctx: &Pkcs11, selection: &Selection) -> Result<Slot> {
    let slots = ctx
        .get_slots_with_token()
        .context("cannot list PKCS#11 slots")?;
    let mut labelled = Vec::new();
    for slot in slots {
        let label = ctx.get_token_info(slot)?.label().trim().to_string();
        labelled.push((slot, label));
    }
    if let Some(wanted) = &selection.token_label {
        return labelled
            .iter()
            .find(|(_, l)| l == wanted)
            .map(|(s, _)| *s)
            .ok_or_else(|| anyhow!("no token labelled {wanted:?}; found: {}", labels(&labelled)));
    }
    // Without a label, only use a slot that shows a certificate before login,
    // so the PIN is never tried against the wrong PIN object.
    let mut with_cert = Vec::new();
    for (slot, label) in &labelled {
        // Uninitialized or unreadable tokens are skipped.
        let Ok(session) = ctx.open_ro_session(*slot) else {
            continue;
        };
        if !session
            .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])?
            .is_empty()
        {
            with_cert.push((*slot, label.clone()));
        }
    }
    match with_cert.len() {
        0 if labelled.is_empty() => {
            bail!("no token found (is the card inserted and pcscd running?)")
        }
        0 => bail!(
            "no token with a certificate found; found: {}",
            labels(&labelled)
        ),
        1 => Ok(with_cert[0].0),
        _ => bail!(
            "more than one token; set NFSE_TOKEN_LABEL to one of: {}",
            labels(&with_cert)
        ),
    }
}

fn labels(slots: &[(Slot, String)]) -> String {
    slots
        .iter()
        .map(|(_, l)| format!("{l:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A signing key with its certificate.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: ObjectHandle,
    pub id: Vec<u8>,
    pub label: String,
    pub cert: Vec<u8>,
}

/// What matters about a certificate when picking the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub is_ca: bool,
    pub valid_now: bool,
    pub digital_signature: bool,
    /// `None` when the certificate has no extended key usage.
    pub client_auth: Option<bool>,
}

impl CertInfo {
    pub fn parse(der: &[u8]) -> Result<CertInfo> {
        let (_, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| anyhow!("bad certificate: {e}"))?;
        let ku = cert.key_usage().ok().flatten();
        let eku = cert.extended_key_usage().ok().flatten();
        let bc = cert.basic_constraints().ok().flatten();
        Ok(CertInfo {
            subject: cert.subject().to_string(),
            is_ca: bc.is_some_and(|b| b.value.ca),
            valid_now: cert.validity().is_valid(),
            digital_signature: ku.is_none_or(|k| k.value.digital_signature()),
            client_auth: eku.map(|e| e.value.client_auth || e.value.any),
        })
    }

    /// Can sign the DPS and authenticate the TLS client.
    pub fn usable(&self) -> bool {
        !self.is_ca && self.valid_now && self.digital_signature && self.client_auth != Some(false)
    }
}

/// Picks the key: by `NFSE_KEY_ID` (hex CKA_ID) or `NFSE_KEY_LABEL` if set;
/// keys sharing one certificate are the same key; otherwise the only key whose
/// certificate is valid and allows signing and client authentication.
pub fn choose_key(mut found: Vec<Candidate>, selection: &Selection) -> Result<Candidate> {
    if found.is_empty() {
        bail!("no signing key with a certificate found on the token");
    }
    let describe = |c: &[Candidate]| -> String {
        c.iter()
            .map(|c| {
                let info = CertInfo::parse(&c.cert)
                    .map(|i| format!("{} (usable: {})", i.subject, i.usable()))
                    .unwrap_or_else(|e| e.to_string());
                format!(
                    "\n  - id {} label {:?}: {info}",
                    hex::encode(&c.id),
                    c.label
                )
            })
            .collect()
    };
    if let Some(wanted) = &selection.key_id {
        let wanted = hex::decode(wanted.trim()).context("NFSE_KEY_ID must be hex")?;
        let all = found.clone();
        found.retain(|c| c.id == wanted);
        if found.is_empty() {
            bail!(
                "no key with id {}; keys:{}",
                hex::encode(&wanted),
                describe(&all)
            );
        }
    }
    if let Some(wanted) = &selection.key_label {
        let all = found.clone();
        found.retain(|c| &c.label == wanted);
        if found.is_empty() {
            bail!("no key labelled {wanted:?}; keys:{}", describe(&all));
        }
    }
    if found.iter().all(|c| c.cert == found[0].cert) {
        return Ok(found.remove(0));
    }
    let usable: Vec<Candidate> = found
        .iter()
        .filter(|c| CertInfo::parse(&c.cert).is_ok_and(|i| i.usable()))
        .cloned()
        .collect();
    match usable.len() {
        0 => bail!(
            "no key has a valid certificate for signing and client authentication; keys:{}",
            describe(&found)
        ),
        _ if usable.iter().all(|c| c.cert == usable[0].cert) => Ok(usable[0].clone()),
        _ => bail!(
            "more than one usable key; set NFSE_KEY_ID to one of these ids:{}",
            describe(&usable)
        ),
    }
}

fn pick_key(session: &Session, selection: &Selection) -> Result<(ObjectHandle, Vec<u8>)> {
    let keys = session.find_objects(&[
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Sign(true),
    ])?;
    let mut found = Vec::new();
    for key in keys {
        let mut id = Vec::new();
        let mut label = String::new();
        for attr in session.get_attributes(key, &[AttributeType::Id, AttributeType::Label])? {
            match attr {
                Attribute::Id(v) => id = v,
                Attribute::Label(v) => label = String::from_utf8_lossy(&v).into_owned(),
                _ => {}
            }
        }
        if let Ok(cert) = find_certificate(session, &id) {
            found.push(Candidate {
                key,
                id,
                label,
                cert,
            });
        }
    }
    let chosen = choose_key(found, selection)?;
    Ok((chosen.key, chosen.id))
}

fn find_certificate(session: &Session, id: &[u8]) -> Result<Vec<u8>> {
    let certs = session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Id(id.to_vec()),
    ])?;
    let cert = *certs
        .first()
        .ok_or_else(|| anyhow!("no certificate for the key"))?;
    match session.get_attributes(cert, &[AttributeType::Value])?.pop() {
        Some(Attribute::Value(der)) => Ok(der),
        _ => bail!("cannot read the certificate"),
    }
}

impl Signer for Token {
    fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    fn sign_digest_info(&self, digest_info: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .session
            .lock()
            .map_err(|_| anyhow!("token session poisoned"))?;
        let Some((pin, lib)) = &self.always_auth else {
            return session
                .sign(&Mechanism::RsaPkcs, self.key, digest_info)
                .context("C_Sign failed");
        };
        // CKA_ALWAYS_AUTHENTICATE: C_SignInit, C_Login(CKU_CONTEXT_SPECIFIC),
        // then C_Sign, which cryptoki has no separate call for.
        session
            .sign_init(&Mechanism::RsaPkcs, self.key)
            .context("C_SignInit failed")?;
        session
            .login(UserType::ContextSpecific, Some(pin))
            .context("context-specific login failed")?;
        // SAFETY: C_Sign has this signature in every PKCS#11 module; the
        // buffers outlive the calls.
        unsafe {
            let c_sign: libloading::Symbol<CSign> =
                lib.get(b"C_Sign").context("module has no C_Sign")?;
            let mut data = digest_info.to_vec();
            let mut len: cryptoki_sys::CK_ULONG = 512;
            let mut out = vec![0u8; len as usize];
            let rv = c_sign(
                session.handle(),
                data.as_mut_ptr(),
                data.len() as _,
                out.as_mut_ptr(),
                &mut len,
            );
            if rv != cryptoki_sys::CKR_OK {
                bail!("C_Sign failed: 0x{rv:x}");
            }
            out.truncate(len as usize);
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins() {
        let path = resolve_module(Some("/x/y.so"), "linux", |_| false).unwrap();
        assert_eq!(path, PathBuf::from("/x/y.so"));
    }

    #[test]
    fn first_existing_candidate_wins() {
        let path = resolve_module(None, "linux", |p| {
            p.starts_with("/usr/lib64") || p.starts_with("/usr/lib/opensc")
        })
        .unwrap();
        assert_eq!(path, PathBuf::from("/usr/lib64/opensc-pkcs11.so"));
        let path = resolve_module(None, "macos", |_| true).unwrap();
        assert_eq!(path, PathBuf::from("/opt/homebrew/lib/opensc-pkcs11.so"));
    }

    #[test]
    fn lists_searched_paths_when_missing() {
        let err = resolve_module(None, "linux", |_| false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("NFSE_PKCS11_MODULE"), "{err}");
        assert!(
            err.contains("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            "{err}"
        );
    }
}

/// A certificate on a token, read without logging in.
#[derive(Debug, Clone)]
pub struct ListedCertificate {
    pub id: Vec<u8>,
    pub label: String,
    pub der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ListedToken {
    pub label: String,
    pub serial: String,
    pub certificates: Vec<ListedCertificate>,
}

/// The tokens of a module and the certificates each shows before login.
pub fn list_certificates(module: &Path) -> Result<Vec<ListedToken>> {
    let ctx = Module::open(module)?;
    let mut tokens = Vec::new();
    for slot in ctx
        .get_slots_with_token()
        .context("cannot list PKCS#11 slots")?
    {
        let info = ctx.get_token_info(slot)?;
        let Ok(session) = ctx.open_ro_session(slot) else {
            continue;
        };
        let mut certificates = Vec::new();
        for cert in session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])? {
            let mut c = ListedCertificate {
                id: Vec::new(),
                label: String::new(),
                der: Vec::new(),
            };
            for attr in session.get_attributes(
                cert,
                &[
                    AttributeType::Id,
                    AttributeType::Label,
                    AttributeType::Value,
                ],
            )? {
                match attr {
                    Attribute::Id(v) => c.id = v,
                    Attribute::Label(v) => c.label = String::from_utf8_lossy(&v).into_owned(),
                    Attribute::Value(v) => c.der = v,
                    _ => {}
                }
            }
            if !c.der.is_empty() {
                certificates.push(c);
            }
        }
        tokens.push(ListedToken {
            label: info.label().trim().to_string(),
            serial: info.serial_number().trim().to_string(),
            certificates,
        });
    }
    Ok(tokens)
}

/// An initialized module, finalized when dropped, so a library caller can
/// open it again (cryptoki does not finalize on drop). Sessions must be
/// dropped first: declare them after the context.
struct Module(Option<Pkcs11>);

impl Module {
    fn open(module: &Path) -> Result<Module> {
        let ctx = Pkcs11::new(module)
            .with_context(|| format!("cannot load PKCS#11 module {}", module.display()))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("C_Initialize failed")?;
        Ok(Module(Some(ctx)))
    }
}

impl std::ops::Deref for Module {
    type Target = Pkcs11;
    fn deref(&self) -> &Pkcs11 {
        self.0.as_ref().expect("open until dropped")
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        if let Some(ctx) = self.0.take()
            && let Err(e) = ctx.finalize()
        {
            log::warn!(target: "nfse::pkcs11", "C_Finalize failed: {e}");
        }
    }
}
