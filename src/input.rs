//! Reads the input JSON and, with `--reuse`, the `infDPS` of an earlier DPS or
//! NFS-e XML, and combines them into the DPS content.

use crate::dps::Environment;
use crate::schema::{self, Elem};
use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::{Map, Value};

/// Fields the tool generates. They are never read from the input and are
/// dropped from a reused XML.
pub const GENERATED: [&str; 5] = ["tpAmb", "dhEmi", "verAplic", "serie", "nDPS"];

/// Defaults applied when the input leaves the field out.
const DEFAULTS: [(&str, &str); 1] = [("tpEmit", "1")];

/// Parses the input JSON. Empty input is an empty object.
pub fn parse_json(text: &str) -> Result<Map<String, Value>> {
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str(text).context("input is not valid JSON")? {
        Value::Object(map) => Ok(map),
        _ => bail!("input JSON must be an object"),
    }
}

/// Extracts the content of the first `infDPS` element of a DPS or NFS-e XML
/// as a tree: elements with children become objects, leaves become strings and
/// repeated siblings become arrays.
pub fn infdps_from_xml(xml: &str) -> Result<Map<String, Value>> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<(String, Map<String, Value>, String)> = Vec::new();
    let mut inside = false;
    loop {
        match reader.read_event().context("cannot parse the XML")? {
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_string();
                if !inside && name == "infDPS" {
                    inside = true;
                    stack.push((name, Map::new(), String::new()));
                } else if inside {
                    stack.push((name, Map::new(), String::new()));
                }
            }
            Event::Empty(e) if inside => {
                let name = e.local_name().as_ref().to_string();
                let parent = &mut stack.last_mut().expect("inside infDPS").1;
                insert(parent, name, Value::String(String::new()));
            }
            Event::Text(t) if inside => {
                let text = t.xml10_content();
                stack.last_mut().expect("inside infDPS").2.push_str(&text);
            }
            Event::GeneralRef(r) if inside => {
                let text = match r.resolve_char_ref().context("bad character reference")? {
                    Some(c) => c.to_string(),
                    None => quick_xml::escape::resolve_predefined_entity(&r.xml10_content())
                        .context("unknown XML entity")?
                        .to_string(),
                };
                stack.last_mut().expect("inside infDPS").2.push_str(&text);
            }
            Event::CData(t) if inside => {
                stack
                    .last_mut()
                    .expect("inside infDPS")
                    .2
                    .push_str(&t.xml10_content());
            }
            Event::End(_) if inside => {
                let (name, children, text) = stack.pop().expect("balanced XML");
                let Some(parent) = stack.last_mut() else {
                    return Ok(children);
                };
                let value = if children.is_empty() {
                    Value::String(text)
                } else {
                    Value::Object(children)
                };
                insert(&mut parent.1, name, value);
            }
            Event::Eof => bail!("no infDPS element found in the XML"),
            _ => {}
        }
    }
}

fn insert(map: &mut Map<String, Value>, name: String, value: Value) {
    match map.get_mut(&name) {
        Some(Value::Array(values)) => values.push(value),
        Some(existing) => {
            let first = existing.take();
            *existing = Value::Array(vec![first, value]);
        }
        None => {
            map.insert(name, value);
        }
    }
}

/// Combines the reused DPS (if any) and the input JSON into validated DPS
/// content, without the generated fields.
pub fn combine(
    reused: Option<Map<String, Value>>,
    input: &Map<String, Value>,
    env: Environment,
) -> Result<Map<String, Value>> {
    let schema = schema::inf_dps(env);
    let provided: Vec<&str> = GENERATED
        .iter()
        .copied()
        .filter(|f| input.contains_key(*f))
        .collect();
    if !provided.is_empty() {
        bail!(
            "these fields are generated and cannot be provided: {}",
            provided.join(", ")
        );
    }
    let mut content = reused.unwrap_or_default();
    for field in GENERATED {
        content.remove(field);
    }
    adapt_layout(&mut content, schema);
    schema::merge(&mut content, input, schema);
    adapt_layout(&mut content, schema);
    for (key, value) in DEFAULTS {
        content
            .entry(key)
            .or_insert_with(|| Value::String(value.to_string()));
    }
    check(&content, schema)?;
    Ok(content)
}

/// Fields that moved between the production layout and the newer staging
/// one: (production path, staging path).
const MOVED: [(&str, &str); 6] = [
    ("IBSCBS.finNFSe", "finNFSe"),
    ("IBSCBS.indDest", "indDest"),
    ("IBSCBS.dest", "dest"),
    ("IBSCBS.valores.trib.gIBSCBS.CST", "IBSCBS.valores.trib.CST"),
    (
        "IBSCBS.valores.trib.gIBSCBS.cClassTrib",
        "IBSCBS.valores.trib.cClassTrib",
    ),
    // NT 009 drops vServMoeda; vFatura is the invoice total in tpMoeda.
    ("serv.comExt.vServMoeda", "serv.comExt.vFatura"),
];

fn in_schema(schema: &Elem, path: &str) -> bool {
    let mut elem = schema;
    for part in path.split('.') {
        match elem.child(part) {
            Some(e) => elem = e,
            None => return false,
        }
    }
    true
}

/// Removes the value at `path`, and any objects left empty on the way.
fn take(map: &mut Map<String, Value>, path: &str) -> Option<Value> {
    match path.split_once('.') {
        None => map.remove(path),
        Some((head, rest)) => {
            let child = map.get_mut(head)?.as_object_mut()?;
            let v = take(child, rest);
            if child.is_empty() {
                map.remove(head);
            }
            v
        }
    }
}

fn put(map: &mut Map<String, Value>, path: &str, value: Value) {
    match path.split_once('.') {
        None => {
            map.insert(path.to_string(), value);
        }
        Some((head, rest)) => {
            let child = map.entry(head).or_insert_with(|| Value::Object(Map::new()));
            if let Some(child) = child.as_object_mut() {
                put(child, rest, value);
            }
        }
    }
}

/// Moves fields to where the target layout has them, so an NFS-e from one
/// environment can be reused in the other.
pub fn adapt_layout(content: &mut Map<String, Value>, schema: &Elem) {
    for (production, staging) in MOVED {
        let (from, to) = if in_schema(schema, staging) {
            (production, staging)
        } else {
            (staging, production)
        };
        if !in_schema(schema, to) {
            continue;
        }
        if let Some(v) = take(content, from) {
            put(content, to, v);
        }
    }
}

/// Validates DPS content that lacks only the generated fields.
pub fn check(content: &Map<String, Value>, schema: &Elem) -> Result<()> {
    let errors: Vec<String> = schema::validate(content, schema, "")
        .into_iter()
        .filter(|e| !GENERATED.iter().any(|g| e == &format!("{g}: required")))
        .collect();
    if !errors.is_empty() {
        bail!("invalid input:\n  - {}", errors.join("\n  - "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub const NOV: &str = include_str!("../tests/fixtures/nfse-ibscbs.xml");

    #[test]
    fn reads_infdps_from_an_nfse() {
        let dps = infdps_from_xml(NOV).unwrap();
        assert_eq!(dps["nDPS"], "4");
        assert_eq!(dps["toma"]["xNome"], "Example Corp");
        assert_eq!(dps["toma"]["end"]["endExt"]["cPais"], "US");
        assert_eq!(dps["serv"]["comExt"]["vServMoeda"], "1000.00");
        assert_eq!(
            dps["IBSCBS"]["valores"]["trib"]["gIBSCBS"]["cClassTrib"],
            "000001"
        );
        assert!(dps.get("Signature").is_none());
    }

    #[test]
    fn reads_entities_and_repeated_elements() {
        let xml = r#"<DPS><infDPS Id="x"><a>A &amp; B&#x41;</a><r>1</r><r>2</r></infDPS></DPS>"#;
        let dps = infdps_from_xml(xml).unwrap();
        assert_eq!(Value::Object(dps), json!({"a": "A & BA", "r": ["1", "2"]}));
    }

    #[test]
    fn reuse_drops_generated_fields_and_applies_overrides() {
        let reused = infdps_from_xml(NOV).unwrap();
        let input = parse_json(
            r#"{"dCompet": "2026-12-01", "valores": {"vServPrest": {"vServ": 6000.5}}}"#,
        )
        .unwrap();
        let content = combine(Some(reused), &input, Environment::Production).unwrap();
        for field in GENERATED {
            assert!(!content.contains_key(field), "{field}");
        }
        assert_eq!(content["dCompet"], "2026-12-01");
        assert_eq!(content["valores"]["vServPrest"]["vServ"], json!(6000.5));
        assert_eq!(content["valores"]["trib"]["tribMun"]["tribISSQN"], "3");
    }

    #[test]
    fn reusing_a_production_nfse_for_staging_moves_fin_nfse() {
        let reused = infdps_from_xml(NOV).unwrap();
        let content = combine(Some(reused.clone()), &Map::new(), Environment::Staging).unwrap();
        assert_eq!(content["finNFSe"], "0");
        assert_eq!(content["indDest"], "0");
        assert_eq!(content["serv"]["comExt"]["vFatura"], "1000.00");
        assert!(content["serv"]["comExt"].get("vServMoeda").is_none());
        assert!(content["IBSCBS"].get("finNFSe").is_none());
        assert!(content["IBSCBS"].get("indDest").is_none());
        let trib = &content["IBSCBS"]["valores"]["trib"];
        assert_eq!(
            Value::clone(trib),
            json!({"CST": "000", "cClassTrib": "000001"})
        );
        // And back, when the input uses the staging layout.
        let input = parse_json(
            r#"{"finNFSe": "0", "indDest": "0", "IBSCBS": {"finNFSe": null, "indDest": null, "valores": {"trib": {"gIBSCBS": null, "CST": "000", "cClassTrib": "000001"}}}}"#,
        )
        .unwrap();
        let content = combine(Some(reused), &input, Environment::Production).unwrap();
        assert_eq!(content["IBSCBS"]["finNFSe"], "0");
        assert_eq!(
            content["IBSCBS"]["valores"]["trib"]["gIBSCBS"]["CST"],
            "000"
        );
        assert!(content.get("finNFSe").is_none());
    }

    #[test]
    fn rejects_generated_fields_in_the_input() {
        let input = parse_json(r#"{"nDPS": "1"}"#).unwrap();
        let err = combine(None, &input, Environment::Production)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nDPS"), "{err}");
    }

    #[test]
    fn lists_every_missing_field_without_reuse() {
        let err = combine(None, &Map::new(), Environment::Production)
            .unwrap_err()
            .to_string();
        for field in [
            "dCompet: required",
            "prest: required",
            "serv: required",
            "valores: required",
        ] {
            assert!(err.contains(field), "{err}");
        }
        assert!(!err.contains("tpEmit"), "tpEmit has a default: {err}");
        assert!(!err.contains("nDPS"), "{err}");
    }

    #[test]
    fn empty_input_is_an_empty_object() {
        assert!(parse_json("  \n").unwrap().is_empty());
        assert!(parse_json("[]").is_err());
    }
}
