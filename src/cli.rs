//! Command line: build the DPS from the input, sign it on the token and,
//! with `--submit`, send it and output the NFS-e.

use crate::connector::{Connector, Endpoints, Issued, SubmitError};
use crate::dps::{self, Dps, Environment, brt};
use crate::input;
use crate::pkcs11::{self, Selection, Token};
use crate::tls;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, FixedOffset};
use clap::Parser;
use serde_json::{Map, Value};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Issues an NFS-e through the Emissor Nacional: reads the input JSON from
/// stdin, builds the DPS, signs it with the A3 token (OpenSC) and, with
/// --submit, sends it to the RFB.
#[derive(Parser, Debug)]
#[command(name = "nfse", version, after_help = ENV_HELP)]
pub struct Args {
    /// Use the staging ("produção restrita") server. The default.
    #[arg(long, conflicts_with = "production")]
    pub staging: bool,
    /// Use the production server, creating a real NFS-e.
    #[arg(long)]
    pub production: bool,
    /// Print the unsigned DPS and quit, without using the token.
    #[arg(long, conflicts_with_all = ["submit", "pdf_outfile"])]
    pub dry_run: bool,
    /// Submit the signed DPS and print the NFS-e XML.
    #[arg(long)]
    pub submit: bool,
    /// Reuse the data of an earlier NFS-e (or DPS) XML, except the DPS id. The
    /// input JSON overrides its fields.
    #[arg(long, value_name = "NFS.XML")]
    pub reuse: Option<PathBuf>,
    /// Set the competência date (dCompet) to today, over --reuse and the input.
    #[arg(long)]
    pub today: bool,
    /// Save the XML to <DPS id>.xml instead of printing it.
    #[arg(long)]
    pub xml_outfile: bool,
    /// Save the DANFSe PDF to <DPS id>.pdf (needs --submit).
    #[arg(long, requires = "submit")]
    pub pdf_outfile: bool,
}

const ENV_HELP: &str = "Environment:
  NFSE_PKCS11_MODULE  PKCS#11 module (default: the first OpenSC module found)
  NFSE_PIN            token PIN (default: asked on the terminal)
  NFSE_TOKEN_LABEL    token to use when there is more than one
  NFSE_KEY_ID         CKA_ID (hex) of the key, when the token has more than one
  NFSE_KEY_LABEL      label of the key, when the token has more than one
  NFSE_CA_BUNDLE      PEM file with extra trusted roots (ICP-Brasil)
  NFSE_SEFIN_URL      Sefin Nacional base URL override
  NFSE_ADN_URL        ADN base URL override";

impl Args {
    pub fn environment(&self) -> Environment {
        if self.production {
            Environment::Production
        } else {
            Environment::Staging
        }
    }
}

/// Settings read from the environment.
#[derive(Debug, Default, Clone)]
pub struct Settings {
    pub module: Option<String>,
    pub pin: Option<String>,
    pub selection: Selection,
    pub ca_bundle: Option<PathBuf>,
    pub sefin_url: Option<String>,
    pub adn_url: Option<String>,
}

impl Settings {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Settings {
        let get = |k: &str| get(k).filter(|v| !v.is_empty());
        Settings {
            module: get("NFSE_PKCS11_MODULE"),
            pin: get("NFSE_PIN"),
            selection: Selection {
                token_label: get("NFSE_TOKEN_LABEL"),
                key_label: get("NFSE_KEY_LABEL"),
                key_id: get("NFSE_KEY_ID"),
            },
            ca_bundle: get("NFSE_CA_BUNDLE").map(PathBuf::from),
            sefin_url: get("NFSE_SEFIN_URL"),
            adn_url: get("NFSE_ADN_URL"),
        }
    }

    pub fn endpoints(&self, env: Environment) -> Endpoints {
        let defaults = Endpoints::for_env(env);
        Endpoints {
            sefin: self.sefin_url.clone().unwrap_or(defaults.sefin),
            adn: self.adn_url.clone().unwrap_or(defaults.adn),
        }
    }
}

/// Reads the environment and the input, and returns the DPS content.
pub fn initialize(
    args: &Args,
    get_env: impl Fn(&str) -> Option<String>,
    stdin: &str,
    now: DateTime<FixedOffset>,
) -> Result<(Settings, Map<String, Value>)> {
    let settings = Settings::from_env(get_env);
    let reused = match &args.reuse {
        Some(path) => {
            let xml = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            Some(
                input::infdps_from_xml(&xml)
                    .with_context(|| format!("cannot reuse {}", path.display()))?,
            )
        }
        None => None,
    };
    let mut overrides = input::parse_json(stdin)?;
    if args.today {
        let today = now.with_timezone(&brt()).format("%Y-%m-%d").to_string();
        overrides.insert("dCompet".into(), Value::String(today));
    }
    let content = input::combine(reused, &overrides, args.environment())?;
    Ok((settings, content))
}

fn read_stdin() -> Result<String> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Ok(String::new());
    }
    let mut text = String::new();
    stdin
        .read_to_string(&mut text)
        .context("cannot read stdin")?;
    Ok(text)
}

fn open_token(settings: &Settings) -> Result<Token> {
    let module = pkcs11::resolve_module(
        settings.module.as_deref(),
        std::env::consts::OS,
        Path::exists,
    )?;
    let pin = settings.pin.clone();
    Token::open(&module, &settings.selection, move || match pin {
        Some(pin) => Ok(pin),
        None => rpassword::prompt_password("Token PIN: ").context("cannot read the PIN"),
    })
}

/// Writes `data` to `<id>.<ext>` or to stdout.
fn output(out: &mut dyn Write, to_file: bool, id: &str, ext: &str, data: &[u8]) -> Result<()> {
    if to_file {
        let path = format!("{id}.{ext}");
        std::fs::write(&path, data).with_context(|| format!("cannot write {path}"))?;
        eprintln!("saved {path}");
    } else {
        out.write_all(data)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

pub fn output_dps(out: &mut dyn Write, args: &Args, dps: &Dps, xml: &str) -> Result<()> {
    output(out, args.xml_outfile, &dps.id, "xml", xml.as_bytes())
}

pub fn output_result(
    out: &mut dyn Write,
    args: &Args,
    dps: &Dps,
    issued: &Issued,
    connector: &Connector,
) -> Result<()> {
    eprintln!("NFS-e issued: {}", issued.chave_acesso);
    output(
        out,
        args.xml_outfile,
        &dps.id,
        "xml",
        issued.nfse_xml.as_bytes(),
    )?;
    if args.pdf_outfile {
        let pdf = connector
            .fetch_danfe(&issued.chave_acesso)
            .context("the NFS-e was issued, but its DANFSe PDF could not be fetched")?;
        output(out, true, &dps.id, "pdf", &pdf)?;
    }
    Ok(())
}

pub fn main() -> Result<()> {
    let args = Args::parse();
    let now = chrono::Utc::now().with_timezone(&brt());
    let (settings, content) = initialize(&args, |k| std::env::var(k).ok(), &read_stdin()?, now)?;
    let env = args.environment();
    let dps = dps::build_dps(&content, env, now)?;
    eprintln!(
        "DPS id: {} ({})",
        dps.id,
        if env == Environment::Production {
            "production"
        } else {
            "staging"
        }
    );
    let mut stdout = std::io::stdout().lock();
    if args.dry_run {
        return output_dps(&mut stdout, &args, &dps, &dps.xml());
    }
    let token = Arc::new(open_token(&settings)?);
    let signed = dps::sign_dps(&dps, token.as_ref())?;
    if !args.submit {
        return output_dps(&mut stdout, &args, &dps, &signed);
    }
    let tls = tls::connector(token, settings.ca_bundle.as_deref())?;
    let connector = Connector::new(tls, settings.endpoints(env));
    match connector.submit_dps(&signed, &dps.id) {
        Ok(issued) => output_result(&mut stdout, &args, &dps, &issued, &connector),
        Err(SubmitError::Unknown(why)) => {
            let path = format!("{}-signed.xml", dps.id);
            std::fs::write(&path, &signed).with_context(|| format!("cannot write {path}"))?;
            bail!(
                "outcome unknown:\n  {why}\nThe signed DPS was saved to {path}. Check whether {} was issued \
                 before submitting again; never submit it with a new DPS id.",
                dps.id
            )
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn args(list: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("nfse").chain(list.iter().copied())).unwrap()
    }

    fn now() -> DateTime<FixedOffset> {
        brt().with_ymd_and_hms(2026, 12, 3, 9, 0, 0).unwrap()
    }

    fn fixture() -> String {
        format!(
            "{}/tests/fixtures/nfse-ibscbs.xml",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn staging_is_the_default() {
        assert_eq!(args(&[]).environment(), Environment::Staging);
        assert_eq!(
            args(&["--production"]).environment(),
            Environment::Production
        );
        assert!(Args::try_parse_from(["nfse", "--staging", "--production"]).is_err());
    }

    #[test]
    fn flag_combinations() {
        assert!(Args::try_parse_from(["nfse", "--dry-run", "--submit"]).is_err());
        assert!(Args::try_parse_from(["nfse", "--pdf-outfile"]).is_err());
        assert!(
            Args::try_parse_from(["nfse", "--submit", "--pdf-outfile", "--xml-outfile"]).is_ok()
        );
    }

    #[test]
    fn settings_from_env_and_url_overrides() {
        let s = Settings::from_env(|k| match k {
            "NFSE_PIN" => Some("1".into()),
            "NFSE_SEFIN_URL" => Some("https://localhost:1/S".into()),
            "NFSE_KEY_LABEL" => Some(String::new()),
            _ => None,
        });
        assert_eq!(s.pin.as_deref(), Some("1"));
        assert_eq!(s.selection.key_label, None);
        let ep = s.endpoints(Environment::Production);
        assert_eq!(ep.sefin, "https://localhost:1/S");
        assert_eq!(ep.adn, "https://adn.nfse.gov.br");
    }

    #[test]
    fn today_overrides_reuse_and_input() {
        let a = args(&["--reuse", &fixture(), "--today"]);
        let (_, content) = initialize(&a, |_| None, r#"{"dCompet":"2020-01-01"}"#, now()).unwrap();
        assert_eq!(content["dCompet"], "2026-12-03");
    }

    #[test]
    fn reuse_keeps_fields_and_input_overrides_them() {
        let a = args(&["--reuse", &fixture()]);
        let (_, content) = initialize(
            &a,
            |_| None,
            r#"{"serv":{"comExt":{"vServMoeda":6000}}}"#,
            now(),
        )
        .unwrap();
        assert_eq!(content["dCompet"], "2026-10-01");
        // Staging (the default) has vFatura where production has vServMoeda.
        assert_eq!(content["serv"]["comExt"]["vFatura"], 6000);
        assert_eq!(content["serv"]["comExt"]["tpMoeda"], "840");
        let a = args(&["--reuse", &fixture(), "--production"]);
        let (_, content) = initialize(
            &a,
            |_| None,
            r#"{"serv":{"comExt":{"vServMoeda":6000}}}"#,
            now(),
        )
        .unwrap();
        assert_eq!(content["serv"]["comExt"]["vServMoeda"], 6000);
    }

    #[test]
    fn missing_fields_fail_without_reuse() {
        let err = initialize(&args(&[]), |_| None, "{}", now())
            .unwrap_err()
            .to_string();
        assert!(err.contains("prest: required"), "{err}");
    }
}
