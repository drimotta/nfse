//! Talks to Sefin Nacional (DPS submission, NFS-e lookup) and ADN (DANFSe
//! PDF) over mutual TLS.

use crate::dps::Environment;
use crate::http::Client;
use crate::tls::TokenTls;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub sefin: String,
    pub adn: String,
}

impl Endpoints {
    pub fn for_env(env: Environment) -> Endpoints {
        match env {
            Environment::Production => Endpoints {
                sefin: "https://sefin.nfse.gov.br/SefinNacional".into(),
                adn: "https://adn.nfse.gov.br".into(),
            },
            Environment::Staging => Endpoints {
                sefin: "https://sefin.producaorestrita.nfse.gov.br/SefinNacional".into(),
                adn: "https://adn.producaorestrita.nfse.gov.br".into(),
            },
        }
    }
}

pub fn gzip_b64(data: &[u8]) -> String {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(data).expect("in-memory write");
    B64.encode(gz.finish().expect("in-memory gzip"))
}

pub fn gunzip_b64(text: &str) -> Result<Vec<u8>> {
    let raw = B64.decode(text.trim()).context("bad base64")?;
    let mut out = Vec::new();
    GzDecoder::new(&raw[..])
        .read_to_end(&mut out)
        .context("bad gzip")?;
    Ok(out)
}

/// Looks up a JSON field ignoring case (real responses vary).
fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

fn text_field(value: &Value, name: &str) -> Option<String> {
    field(value, name)
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The messages of an error response (`erros`, `erro`, object or array).
pub fn error_messages(body: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["erros", "erro"] {
        let items = match field(body, key) {
            Some(Value::Array(items)) => items.clone(),
            Some(v @ Value::Object(_)) => vec![v.clone()],
            _ => continue,
        };
        for item in items {
            let parts: Vec<String> = ["codigo", "descricao", "complemento", "mensagem"]
                .iter()
                .filter_map(|k| text_field(&item, k))
                .filter(|s| !s.is_empty())
                .collect();
            out.push(if parts.is_empty() {
                item.to_string()
            } else {
                parts.join(" - ")
            });
        }
    }
    out
}

#[derive(Debug)]
pub enum SubmitError {
    /// The DPS was rejected; it can be fixed and sent again as a new DPS.
    Rejected(Vec<String>),
    /// The outcome is unknown; check `GET /dps/{id}` before sending anything.
    Unknown(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::Rejected(errors) => {
                write!(f, "DPS rejected:\n  - {}", errors.join("\n  - "))
            }
            SubmitError::Unknown(why) => write!(
                f,
                "outcome unknown ({why}); do not resend before checking the DPS id"
            ),
        }
    }
}

impl std::error::Error for SubmitError {}

#[derive(Debug, Clone)]
pub struct Issued {
    pub chave_acesso: String,
    pub nfse_xml: String,
}

pub struct Connector {
    client: Client,
    endpoints: Endpoints,
    /// Waits between lookups after an uncertain submission.
    pub recovery_delays: Vec<Duration>,
}

impl Connector {
    pub fn new(tls: TokenTls, endpoints: Endpoints) -> Connector {
        Connector {
            client: Client::new(tls),
            endpoints,
            recovery_delays: [2, 5, 10].map(Duration::from_secs).to_vec(),
        }
    }

    fn get_json(&self, url: &str) -> std::result::Result<Option<Value>, String> {
        let resp = self
            .client
            .request("GET", url, "application/json", None)
            .map_err(|e| format!("{e:#}"))?;
        match resp.status {
            200..=299 => serde_json::from_slice(&resp.body)
                .map(Some)
                .map_err(|e| format!("bad JSON from {url}: {e}")),
            404 => Ok(None),
            code => Err(format!("HTTP {code} from {url}: {}", resp.text())),
        }
    }

    /// The access key of the NFS-e generated from a DPS, if there is one.
    pub fn lookup_dps(&self, dps_id: &str) -> Result<Option<String>> {
        let url = format!("{}/dps/{dps_id}", self.endpoints.sefin);
        match self.get_json(&url).map_err(|e| anyhow!(e))? {
            Some(body) => Ok(Some(
                text_field(&body, "chaveAcesso")
                    .ok_or_else(|| anyhow!("no chaveAcesso in {body}"))?,
            )),
            None => Ok(None),
        }
    }

    /// Sends the signed DPS. When the outcome is uncertain (network error,
    /// 5xx), looks the DPS id up instead of sending it again, and sends the
    /// same bytes once more only if it is still unknown.
    pub fn submit_dps(
        &self,
        signed_xml: &str,
        dps_id: &str,
    ) -> std::result::Result<Issued, SubmitError> {
        let body = json!({ "dpsXmlGZipB64": gzip_b64(signed_xml.as_bytes()) });
        let mut errors: Vec<String> = Vec::new();
        for attempt in 0..2 {
            match self.post(&body) {
                Ok(issued) => return Ok(issued),
                Err(PostError::Rejected(errors_list)) => {
                    if attempt == 0 {
                        return Err(SubmitError::Rejected(errors_list));
                    }
                    // A rejection of the resend may be the duplicate of a DPS
                    // the first attempt did create.
                    errors.push(format!("resend rejected: {}", errors_list.join("; ")));
                }
                Err(PostError::Uncertain(why)) => errors.push(format!("submit: {why}")),
            }
            for delay in &self.recovery_delays {
                std::thread::sleep(*delay);
                match self.lookup_dps(dps_id) {
                    Ok(Some(chave)) => {
                        return match self.fetch_xml(&chave) {
                            Ok(nfse_xml) => Ok(Issued {
                                chave_acesso: chave,
                                nfse_xml,
                            }),
                            Err(e) => Err(SubmitError::Unknown(format!(
                                "NFS-e {chave} exists but cannot be fetched: {e:#}"
                            ))),
                        };
                    }
                    Ok(None) => {}
                    Err(e) => errors.push(format!("lookup: {e:#}")),
                }
            }
        }
        errors.dedup();
        Err(SubmitError::Unknown(errors.join("\n  ")))
    }

    fn post(&self, body: &Value) -> std::result::Result<Issued, PostError> {
        let url = format!("{}/nfse", self.endpoints.sefin);
        let payload = serde_json::to_vec(body).expect("JSON");
        let resp = self
            .client
            .request("POST", &url, "application/json", Some(&payload))
            .map_err(|e| PostError::Uncertain(format!("{e:#}")))?;
        match resp.status {
            200..=299 => {
                let body: Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| PostError::Uncertain(format!("bad JSON: {e}")))?;
                let chave = text_field(&body, "chaveAcesso")
                    .ok_or_else(|| PostError::Uncertain(format!("no chaveAcesso in {body}")))?;
                let xml = text_field(&body, "nfseXmlGZipB64")
                    .ok_or_else(|| PostError::Uncertain(format!("no nfseXmlGZipB64 in {body}")))?;
                let xml = gunzip_b64(&xml).map_err(|e| PostError::Uncertain(format!("{e:#}")))?;
                Ok(Issued {
                    chave_acesso: chave,
                    nfse_xml: String::from_utf8_lossy(&xml).into_owned(),
                })
            }
            code @ 400..=499 => {
                let text = resp.text();
                let messages = serde_json::from_str::<Value>(&text)
                    .map(|v| error_messages(&v))
                    .unwrap_or_default();
                let messages = if messages.is_empty() {
                    vec![format!("HTTP {code}: {text}")]
                } else {
                    messages
                };
                Err(PostError::Rejected(messages))
            }
            code => Err(PostError::Uncertain(format!(
                "HTTP {code}: {}",
                resp.text()
            ))),
        }
    }

    /// The NFS-e XML for an access key.
    pub fn fetch_xml(&self, chave: &str) -> Result<String> {
        let url = format!("{}/nfse/{chave}", self.endpoints.sefin);
        let body = self
            .get_json(&url)
            .map_err(|e| anyhow!(e))?
            .ok_or_else(|| anyhow!("NFS-e {chave} not found"))?;
        let xml = text_field(&body, "nfseXmlGZipB64")
            .ok_or_else(|| anyhow!("no nfseXmlGZipB64 in {body}"))?;
        String::from_utf8(gunzip_b64(&xml)?).context("NFS-e XML is not UTF-8")
    }

    /// The DANFSe PDF for an access key.
    pub fn fetch_danfe(&self, chave: &str) -> Result<Vec<u8>> {
        let url = format!("{}/danfse/{chave}", self.endpoints.adn);
        let resp = self
            .client
            .request("GET", &url, "application/pdf", None)
            .context("DANFSe")?;
        if resp.status != 200 {
            bail!("DANFSe: HTTP {} from {url}", resp.status);
        }
        if !resp.body.starts_with(b"%PDF") {
            bail!("DANFSe response is not a PDF");
        }
        Ok(resp.body)
    }
}

enum PostError {
    Rejected(Vec<String>),
    Uncertain(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_round_trip() {
        assert_eq!(gunzip_b64(&gzip_b64(b"<DPS/>")).unwrap(), b"<DPS/>");
    }

    #[test]
    fn error_messages_tolerate_shapes_and_case() {
        let body = json!({"erros": [{"Codigo": "E0004", "Descricao": "Id invalido"}], "erro": {"mensagem": "x"}});
        assert_eq!(error_messages(&body), ["E0004 - Id invalido", "x"]);
        assert!(error_messages(&json!({})).is_empty());
    }

    #[test]
    fn endpoints_per_environment() {
        assert!(
            Endpoints::for_env(Environment::Staging)
                .sefin
                .contains("producaorestrita")
        );
        assert_eq!(
            Endpoints::for_env(Environment::Production).adn,
            "https://adn.nfse.gov.br"
        );
    }
}
