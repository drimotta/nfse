//! Builds the DPS XML and signs it (XMLDSig enveloped, RSA-SHA256, inclusive
//! C14N).
//!
//! The XML is written directly in canonical form (no whitespace, no comments,
//! start/end tag pairs, C14N escaping), so the canonical form of `infDPS` is
//! its own bytes plus the inherited default namespace declaration.

use crate::input::GENERATED;
use crate::schema;
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Datelike, FixedOffset, Timelike};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const NS: &str = "http://www.sped.fazenda.gov.br/nfse";
pub const VERSION: &str = "1.01";
pub const APP_VERSION: &str = concat!("nfse-cli_", env!("CARGO_PKG_VERSION"));
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// "Produção restrita" (homologação), `tpAmb` 2.
    Staging,
    /// Production, `tpAmb` 1.
    Production,
}

impl Environment {
    pub fn tp_amb(self) -> &'static str {
        match self {
            Environment::Production => "1",
            Environment::Staging => "2",
        }
    }
}

/// Brasília time. Brazil has had no daylight saving time since 2019.
pub fn brt() -> FixedOffset {
    FixedOffset::west_opt(3 * 3600).expect("valid offset")
}

/// The DPS series (`YYYY`) and number (`MMDDHHmmSS`, without leading zeros,
/// as the schema requires) for an emission timestamp.
pub fn dps_numbers(at: &DateTime<FixedOffset>) -> (String, String) {
    let at = at.with_timezone(&brt());
    let serie = format!("{:04}", at.year());
    let n: u64 = format!(
        "{:02}{:02}{:02}{:02}{:02}",
        at.month(),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
    .parse()
    .expect("digits");
    (serie, n.to_string())
}

/// `DPS` + cLocEmi(7) + tpInsc(1) + inscrição federal(14) + série(5) + nDPS(15).
pub fn dps_id(content: &Map<String, Value>, serie: &str, n_dps: &str) -> Result<String> {
    let text = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);
    let c_loc_emi = text(content.get("cLocEmi")).ok_or_else(|| anyhow!("cLocEmi is required"))?;
    let prest = content
        .get("prest")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("prest is required"))?;
    let (tp_insc, insc) = if let Some(cnpj) = text(prest.get("CNPJ")) {
        ("2", cnpj)
    } else if let Some(cpf) = text(prest.get("CPF")) {
        ("1", cpf)
    } else {
        bail!("prest.CNPJ or prest.CPF is required to build the DPS id");
    };
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if c_loc_emi.len() != 7 || !digits(&c_loc_emi) {
        bail!("cLocEmi must be a 7-digit IBGE code, got {c_loc_emi:?}");
    }
    if insc.len() > 14 || !digits(&insc) {
        bail!("prest CNPJ/CPF must have only digits, got {insc:?}");
    }
    Ok(format!(
        "DPS{c_loc_emi}{tp_insc}{insc:0>14}{serie:0>5}{n_dps:0>15}"
    ))
}

/// An unsigned DPS.
#[derive(Debug, Clone)]
pub struct Dps {
    pub id: String,
    /// The `infDPS` element as written in the document.
    pub inf_dps: String,
}

impl Dps {
    /// The unsigned DPS document.
    pub fn xml(&self) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><DPS xmlns="{NS}" versao="{VERSION}">{}</DPS>"#,
            self.inf_dps
        )
    }

    /// The canonical form of `infDPS` (inclusive C14N of the subtree), which
    /// carries the default namespace declared on `DPS`.
    pub fn inf_dps_c14n(&self) -> String {
        self.inf_dps
            .replacen("<infDPS ", &format!(r#"<infDPS xmlns="{NS}" "#), 1)
    }
}

/// Builds the DPS from validated content, adding the generated fields. The
/// series and number come from the timestamp.
pub fn build_dps(
    content: &Map<String, Value>,
    env: Environment,
    now: DateTime<FixedOffset>,
) -> Result<Dps> {
    let (serie, n_dps) = dps_numbers(&now);
    build_dps_numbered(content, env, now, &serie, &n_dps)
}

/// Builds the DPS with the given series and number, which the caller keeps
/// unique (a DPS id is never used twice).
pub fn build_dps_numbered(
    content: &Map<String, Value>,
    env: Environment,
    now: DateTime<FixedOffset>,
    serie: &str,
    n_dps: &str,
) -> Result<Dps> {
    let now = now.with_timezone(&brt());
    let mut full = content.clone();
    let generated = [
        env.tp_amb().to_string(),
        now.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        APP_VERSION.to_string(),
        serie.to_string(),
        n_dps.to_string(),
    ];
    for (field, value) in GENERATED.iter().zip(generated) {
        full.insert(field.to_string(), Value::String(value));
    }
    assemble(&full, env)
}

/// Validates the full `infDPS` content and writes it.
fn assemble(full: &Map<String, Value>, env: Environment) -> Result<Dps> {
    let schema = schema::inf_dps(env);
    let errors = schema::validate(full, schema, "");
    if !errors.is_empty() {
        bail!("invalid DPS:\n  - {}", errors.join("\n  - "));
    }
    let text = |f: &str| full.get(f).and_then(Value::as_str).unwrap_or_default();
    let (serie, n_dps) = (text("serie"), text("nDPS"));
    let digits =
        |s: &str, max: usize| (1..=max).contains(&s.len()) && s.chars().all(|c| c.is_ascii_digit());
    if !digits(serie, 5) {
        bail!("invalid DPS:\n  - serie: 1 to 5 digits, got {serie:?}");
    }
    if !digits(n_dps, 15) || n_dps.starts_with('0') {
        bail!("invalid DPS:\n  - nDPS: 1 to 15 digits without leading zeros, got {n_dps:?}");
    }
    let id = dps_id(full, serie, n_dps)?;
    let mut inf_dps = format!(r#"<infDPS Id="{id}">"#);
    schema::write_children(&mut inf_dps, full, schema).map_err(|e| anyhow!(e))?;
    inf_dps.push_str("</infDPS>");
    Ok(Dps { id, inf_dps })
}

impl Dps {
    /// Reads back an unsigned DPS written by [`Dps::xml`]. Anything else is
    /// refused, including the same content written differently, so what is
    /// signed is exactly what was built and checked.
    pub fn from_unsigned_xml(xml: &str) -> Result<Dps> {
        let head = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><DPS xmlns="{NS}" versao="{VERSION}">"#
        );
        let inf_dps = xml
            .strip_prefix(&head)
            .and_then(|rest| rest.strip_suffix("</DPS>"))
            .filter(|inf| inf.starts_with("<infDPS Id=\"") && inf.ends_with("</infDPS>"))
            .ok_or_else(|| anyhow!("not an unsigned DPS"))?;
        let full = crate::input::infdps_from_xml(xml)?;
        let env = match full.get("tpAmb").and_then(Value::as_str) {
            Some("1") => Environment::Production,
            Some("2") => Environment::Staging,
            other => bail!("bad tpAmb {other:?}"),
        };
        let dps = assemble(&full, env)?;
        if dps.inf_dps != inf_dps {
            bail!("the DPS is not in the form this library writes");
        }
        Ok(dps)
    }
}

/// An RSA key that signs a PKCS#1 v1.5 `DigestInfo` (`CKM_RSA_PKCS`).
pub trait Signer {
    /// The signer's certificate, DER.
    fn certificate(&self) -> &[u8];
    fn sign_digest_info(&self, digest_info: &[u8]) -> Result<Vec<u8>>;
}

/// The DER `DigestInfo` prefixes of PKCS#1 v1.5 signatures (RFC 8017, 9.2).
pub const SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
pub const SHA384_PREFIX: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
pub const SHA512_PREFIX: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

pub fn digest_info(prefix: &[u8], digest: &[u8]) -> Vec<u8> {
    [prefix, digest].concat()
}

fn signed_info(id: &str, digest_b64: &str) -> String {
    format!(
        concat!(
            r#"<SignedInfo xmlns="{ns}">"#,
            r#"<CanonicalizationMethod Algorithm="{c14n}"></CanonicalizationMethod>"#,
            r#"<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>"#,
            r##"<Reference URI="#{id}"><Transforms>"##,
            r#"<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>"#,
            r#"<Transform Algorithm="{c14n}"></Transform></Transforms>"#,
            r#"<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>"#,
            r#"<DigestValue>{digest}</DigestValue></Reference></SignedInfo>"#
        ),
        ns = DSIG_NS,
        c14n = C14N,
        id = id,
        digest = digest_b64
    )
}

/// Signs the DPS and returns the signed document. Its bytes must be sent as
/// they are.
pub fn sign_dps(dps: &Dps, signer: &dyn Signer) -> Result<String> {
    let digest = B64.encode(Sha256::digest(dps.inf_dps_c14n().as_bytes()));
    let signed_info = signed_info(&dps.id, &digest);
    let hash = Sha256::digest(signed_info.as_bytes());
    let signature = signer.sign_digest_info(&digest_info(&SHA256_PREFIX, &hash))?;
    // Inside <Signature xmlns=...> the declaration on SignedInfo is redundant;
    // C14N of SignedInfo puts it back, so the signed bytes are unchanged.
    let signed_info = signed_info.replacen(&format!(r#" xmlns="{DSIG_NS}""#), "", 1);
    Ok(format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?><DPS xmlns="{ns}" versao="{version}">{inf}"#,
            r#"<Signature xmlns="{dsig}">{si}<SignatureValue>{sig}</SignatureValue>"#,
            r#"<KeyInfo><X509Data><X509Certificate>{cert}</X509Certificate></X509Data></KeyInfo>"#,
            r#"</Signature></DPS>"#
        ),
        ns = NS,
        version = VERSION,
        inf = dps.inf_dps,
        dsig = DSIG_NS,
        si = signed_info,
        sig = B64.encode(signature),
        cert = B64.encode(signer.certificate()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{combine, infdps_from_xml};
    use chrono::TimeZone;

    const NOV: &str = include_str!("../tests/fixtures/nfse-ibscbs.xml");
    const MAR: &str = include_str!("../tests/fixtures/dps-pis-cofins.xml");

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<FixedOffset> {
        brt().with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    /// The `infDPS` element of a sample, as written there.
    fn sample_inf_dps(xml: &str) -> String {
        let start = xml.find("<infDPS").unwrap();
        let end = xml.find("</infDPS>").unwrap() + "</infDPS>".len();
        xml[start..end].to_string()
    }

    fn replace_tag(xml: &str, tag: &str, value: &str) -> String {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = xml.find(&open).unwrap() + open.len();
        let end = xml[start..].find(&close).unwrap() + start;
        format!("{}{value}{}", &xml[..start], &xml[end..])
    }

    #[test]
    fn numbers_come_from_the_timestamp_without_leading_zeros() {
        assert_eq!(
            dps_numbers(&at(2026, 11, 26, 10, 5, 9)),
            ("2026".into(), "1126100509".into())
        );
        assert_eq!(
            dps_numbers(&at(2027, 1, 2, 0, 0, 0)),
            ("2027".into(), "102000000".into())
        );
        // Converted to Brasília time first.
        let utc = chrono::Utc
            .with_ymd_and_hms(2027, 1, 1, 2, 0, 0)
            .unwrap()
            .fixed_offset();
        assert_eq!(dps_numbers(&utc), ("2026".into(), "1231230000".into()));
    }

    #[test]
    fn id_pads_series_and_number() {
        let content = infdps_from_xml(NOV).unwrap();
        assert_eq!(
            dps_id(&content, "70000", "4").unwrap(),
            "DPS310620021234567800019570000000000000000004"
        );
        assert_eq!(
            dps_id(&content, "2026", "102000000").unwrap(),
            "DPS310620021234567800019502026000000102000000"
        );
    }

    #[test]
    fn rebuilding_a_sample_gives_the_same_xml_except_generated_fields() {
        for sample in [NOV, MAR] {
            let content = combine(
                Some(infdps_from_xml(sample).unwrap()),
                &Map::new(),
                Environment::Production,
            )
            .unwrap();
            let now = at(2026, 11, 26, 10, 5, 9);
            let dps = build_dps(&content, Environment::Production, now).unwrap();
            assert_eq!(dps.id, "DPS310620021234567800019502026000001126100509");

            let mut expected = sample_inf_dps(sample);
            let id_start = expected.find("Id=\"").unwrap() + 4;
            let id_end = expected[id_start..].find('"').unwrap() + id_start;
            expected.replace_range(id_start..id_end, &dps.id);
            for (tag, value) in [
                ("tpAmb", "1"),
                ("dhEmi", "2026-11-26T10:05:09-03:00"),
                ("verAplic", APP_VERSION),
                ("serie", "2026"),
                ("nDPS", "1126100509"),
            ] {
                expected = replace_tag(&expected, tag, value);
            }
            assert_eq!(dps.inf_dps, expected);
        }
    }

    #[test]
    fn staging_uses_tp_amb_2() {
        let content = combine(
            Some(infdps_from_xml(NOV).unwrap()),
            &Map::new(),
            Environment::Staging,
        )
        .unwrap();
        let dps = build_dps(&content, Environment::Staging, at(2026, 11, 26, 10, 5, 9)).unwrap();
        assert!(dps.inf_dps.contains("<tpAmb>2</tpAmb>"));
        assert!(
            dps.inf_dps
                .contains("<tpEmit>1</tpEmit><finNFSe>0</finNFSe><cLocEmi>"),
            "{}",
            dps.inf_dps
        );
        assert!(
            dps.inf_dps.contains("<IBSCBS><indFinal>"),
            "{}",
            dps.inf_dps
        );
        assert!(dps.xml().starts_with(r#"<?xml version="1.0" encoding="UTF-8"?><DPS xmlns="http://www.sped.fazenda.gov.br/nfse" versao="1.01"><infDPS Id="DPS"#));
    }

    #[test]
    fn explicit_numbers_are_used_instead_of_the_timestamp() {
        let content = combine(
            Some(infdps_from_xml(NOV).unwrap()),
            &Map::new(),
            Environment::Staging,
        )
        .unwrap();
        let now = at(2026, 11, 26, 10, 5, 9);
        let dps = build_dps_numbered(&content, Environment::Staging, now, "1", "42").unwrap();
        assert_eq!(dps.id, "DPS310620021234567800019500001000000000000042");
        assert!(
            dps.inf_dps.contains("<serie>1</serie><nDPS>42</nDPS>"),
            "{}",
            dps.inf_dps
        );
        assert!(
            dps.inf_dps
                .contains("<dhEmi>2026-11-26T10:05:09-03:00</dhEmi>")
        );
    }

    #[test]
    fn explicit_numbers_must_fit_the_schema() {
        let content = combine(
            Some(infdps_from_xml(NOV).unwrap()),
            &Map::new(),
            Environment::Staging,
        )
        .unwrap();
        let now = at(2026, 11, 26, 10, 5, 9);
        for (serie, n) in [
            ("1", "042"),
            ("1", ""),
            ("", "1"),
            ("1", "1234567890123456"),
            ("x", "1"),
        ] {
            assert!(
                build_dps_numbered(&content, Environment::Staging, now, serie, n).is_err(),
                "serie {serie:?} nDPS {n:?} accepted"
            );
        }
    }

    #[test]
    fn an_unsigned_dps_reads_back_from_its_xml() {
        let content = combine(
            Some(infdps_from_xml(NOV).unwrap()),
            &Map::new(),
            Environment::Staging,
        )
        .unwrap();
        let dps = build_dps(&content, Environment::Staging, at(2026, 11, 26, 10, 5, 9)).unwrap();
        let back = Dps::from_unsigned_xml(&dps.xml()).unwrap();
        assert_eq!(back.id, dps.id);
        assert_eq!(back.inf_dps, dps.inf_dps);
    }

    #[test]
    fn only_an_unsigned_dps_in_canonical_form_reads_back() {
        let content = combine(
            Some(infdps_from_xml(NOV).unwrap()),
            &Map::new(),
            Environment::Staging,
        )
        .unwrap();
        let dps = build_dps(&content, Environment::Staging, at(2026, 11, 26, 10, 5, 9)).unwrap();
        let xml = dps.xml();
        let signer = FakeSigner(vec![Default::default()]);
        let bad = [
            sign_dps(&dps, &signer).unwrap(),
            xml.replace("<infDPS ", "<infDPS  "),
            xml.replace("</DPS>", "</DPS> "),
            xml.replace("</infDPS>", "</infDPS><x></x>"),
            xml.replace(NS, "urn:other"),
            xml.replace("versao=\"1.01\"", "versao=\"9\""),
            xml.replace(&format!("Id=\"{}\"", dps.id), "Id=\"DPS1\""),
            xml.replace("<tpAmb>", "<!-- x --><tpAmb>"),
            "<DPS/>".to_string(),
        ];
        for xml in bad {
            assert!(Dps::from_unsigned_xml(&xml).is_err(), "accepted {xml}");
        }
    }

    struct FakeSigner(Vec<std::cell::RefCell<Vec<u8>>>);

    impl Signer for FakeSigner {
        fn certificate(&self) -> &[u8] {
            b"cert"
        }
        fn sign_digest_info(&self, digest_info: &[u8]) -> Result<Vec<u8>> {
            *self.0[0].borrow_mut() = digest_info.to_vec();
            Ok(b"sig".to_vec())
        }
    }

    #[test]
    fn signature_references_infdps_and_signs_the_signed_info() {
        let content = combine(
            Some(infdps_from_xml(NOV).unwrap()),
            &Map::new(),
            Environment::Staging,
        )
        .unwrap();
        let dps = build_dps(&content, Environment::Staging, at(2026, 11, 26, 10, 5, 9)).unwrap();
        let signer = FakeSigner(vec![Default::default()]);
        let signed = sign_dps(&dps, &signer).unwrap();

        assert!(signed.contains(&dps.inf_dps));
        assert!(signed.ends_with("</Signature></DPS>"));
        assert!(signed.contains(&format!(r##"<Reference URI="#{}">"##, dps.id)));
        assert!(signed.contains("<SignatureValue>c2ln</SignatureValue>"));
        assert!(signed.contains("<X509Certificate>Y2VydA==</X509Certificate>"));

        let digest = B64.encode(Sha256::digest(dps.inf_dps_c14n().as_bytes()));
        assert!(signed.contains(&format!("<DigestValue>{digest}</DigestValue>")));
        let expected = digest_info(
            &SHA256_PREFIX,
            &Sha256::digest(signed_info(&dps.id, &digest).as_bytes()),
        );
        assert_eq!(*signer.0[0].borrow(), expected);
    }
}
