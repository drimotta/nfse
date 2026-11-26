//! The DPS element tree (XSD v1.01), used to validate input, merge overrides
//! and serialize `infDPS` in schema order.
//!
//! The tree is generated from the XSD into `dps_schema.txt`: one element per
//! line, `indent name min max type`, with `(choice)` grouping the elements
//! indented below it.

use crate::dps::Environment;
use serde_json::{Map, Value};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Elem {
    pub name: String,
    pub min: u32,
    /// `None` means unbounded.
    pub max: Option<u32>,
    pub ty: String,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone)]
pub enum Item {
    Elem(Elem),
    /// The members, and whether the whole choice may be left out.
    Choice(Vec<Elem>, bool),
}

impl Elem {
    pub fn is_leaf(&self) -> bool {
        self.items.is_empty()
    }

    pub fn repeats(&self) -> bool {
        self.max.is_none_or(|m| m > 1)
    }

    /// Direct child elements, choice members included, in schema order.
    pub fn children(&self) -> impl Iterator<Item = &Elem> {
        self.items.iter().flat_map(|item| match item {
            Item::Elem(e) => std::slice::from_ref(e).iter(),
            Item::Choice(members, _) => members.iter(),
        })
    }

    pub fn child(&self, name: &str) -> Option<&Elem> {
        self.children().find(|e| e.name == name)
    }

    /// The other members of the choice `name` belongs to.
    pub fn choice_siblings(&self, name: &str) -> Vec<&str> {
        for item in &self.items {
            if let Item::Choice(members, _) = item
                && members.iter().any(|m| m.name == name)
            {
                return members
                    .iter()
                    .filter(|m| m.name != name)
                    .map(|m| m.name.as_str())
                    .collect();
            }
        }
        Vec::new()
    }
}

/// The `infDPS` element of the layout each environment accepts. Staging
/// ("produção restrita") already runs a newer v1.01 XSD than production.
/// Regenerate with `tools/xsd2schema.py` when the XSD package changes.
pub fn inf_dps(env: Environment) -> &'static Elem {
    static PRODUCTION: OnceLock<Elem> = OnceLock::new();
    static STAGING: OnceLock<Elem> = OnceLock::new();
    match env {
        Environment::Production => PRODUCTION.get_or_init(|| {
            parse(include_str!("schema/production.txt")).expect("valid DPS schema")
        }),
        Environment::Staging => STAGING
            .get_or_init(|| parse(include_str!("schema/staging.txt")).expect("valid DPS schema")),
    }
}

pub fn parse(text: &str) -> Result<Elem, String> {
    let lines: Vec<(usize, &str)> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| (l.len() - l.trim_start().len(), l.trim()))
        .collect();
    let mut pos = 0;
    let root = parse_elem(&lines, &mut pos)?;
    if pos != lines.len() {
        return Err(format!("unexpected line: {}", lines[pos].1));
    }
    Ok(root)
}

fn parse_elem(lines: &[(usize, &str)], pos: &mut usize) -> Result<Elem, String> {
    let (indent, line) = lines[*pos];
    let parts: Vec<&str> = line.split_whitespace().collect();
    let [name, min, max, ty] = parts[..] else {
        return Err(format!("bad schema line: {line}"));
    };
    let mut elem = Elem {
        name: name.to_string(),
        min: min.parse().map_err(|_| format!("bad min: {line}"))?,
        max: if max == "*" {
            None
        } else {
            Some(max.parse().map_err(|_| format!("bad max: {line}"))?)
        },
        ty: ty.to_string(),
        items: Vec::new(),
    };
    *pos += 1;
    while *pos < lines.len() && lines[*pos].0 > indent {
        let (child_indent, child) = lines[*pos];
        if child == "(choice)" || child == "(choice?)" {
            *pos += 1;
            let mut members = Vec::new();
            while *pos < lines.len() && lines[*pos].0 > child_indent {
                members.push(parse_elem(lines, pos)?);
            }
            elem.items.push(Item::Choice(members, child == "(choice?)"));
        } else {
            elem.items.push(Item::Elem(parse_elem(lines, pos)?));
        }
    }
    Ok(elem)
}

/// Deep-merges `overlay` into `base`. A `null` in the overlay removes the key,
/// and setting one member of a choice removes the other members.
pub fn merge(base: &mut Map<String, Value>, overlay: &Map<String, Value>, elem: &Elem) {
    for (key, value) in overlay {
        if value.is_null() {
            base.remove(key);
            continue;
        }
        for sibling in elem.choice_siblings(key) {
            base.remove(sibling);
        }
        match (base.get_mut(key), value, elem.child(key)) {
            (Some(Value::Object(b)), Value::Object(o), Some(child)) if !child.is_leaf() => {
                merge(b, o, child)
            }
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Checks `value` (the content of `elem`) against the schema and returns every
/// problem found, as `path: message`.
pub fn validate(value: &Map<String, Value>, elem: &Elem, path: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for key in value.keys() {
        if elem.child(key).is_none() {
            errors.push(format!("{}: unknown field", join(path, key)));
        }
    }
    for item in &elem.items {
        match item {
            Item::Elem(child) => match value.get(&child.name) {
                None if child.min > 0 => {
                    errors.push(format!("{}: required", join(path, &child.name)))
                }
                None => {}
                Some(v) => validate_occurrences(v, child, &join(path, &child.name), &mut errors),
            },
            Item::Choice(members, optional) => {
                let present: Vec<&Elem> = members
                    .iter()
                    .filter(|m| value.contains_key(&m.name))
                    .collect();
                let names = members
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>()
                    .join("|");
                // A choice is satisfied empty if it is optional or has an
                // optional member.
                let required = !optional && members.iter().all(|m| m.min > 0);
                match present.len() {
                    0 if required => {
                        errors.push(format!("{}: one of {names} is required", join(path, "*")))
                    }
                    0 => {}
                    1 => {
                        let m = present[0];
                        validate_occurrences(&value[&m.name], m, &join(path, &m.name), &mut errors);
                    }
                    _ => errors.push(format!(
                        "{}: only one of {names} is allowed",
                        join(path, "*")
                    )),
                }
            }
        }
    }
    errors
}

fn validate_occurrences(value: &Value, elem: &Elem, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::Array(values) if elem.repeats() => {
            if values.is_empty() {
                errors.push(format!("{path}: must not be empty"));
            }
            if let Some(max) = elem.max
                && values.len() > max as usize
            {
                errors.push(format!("{path}: at most {max} items"));
            }
            for (i, v) in values.iter().enumerate() {
                validate_one(v, elem, &format!("{path}[{i}]"), errors);
            }
        }
        Value::Array(_) => errors.push(format!("{path}: a single value is expected")),
        v => validate_one(v, elem, path, errors),
    }
}

fn validate_one(value: &Value, elem: &Elem, path: &str, errors: &mut Vec<String>) {
    if elem.is_leaf() {
        if let Err(e) = leaf_text(value, elem) {
            errors.push(format!("{path}: {e}"));
        }
    } else if let Value::Object(map) = value {
        errors.extend(validate(map, elem, path));
    } else {
        errors.push(format!("{path}: an object is expected"));
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

/// Number of decimal places of a `TSDec..V2`-style type, if it is a decimal.
fn decimals(ty: &str) -> Option<usize> {
    let rest = ty.strip_prefix("TSDec")?;
    let (_, places) = rest.split_once('V')?;
    places.parse().ok()
}

/// The text of a leaf. Decimal types are normalized to their fixed number of
/// decimal places, so `1000` becomes `1000.00`.
pub fn leaf_text(value: &Value, elem: &Elem) -> Result<String, String> {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Err("a string or number is expected".into()),
    };
    if text.trim().is_empty() {
        return Err("must not be empty".into());
    }
    match decimals(&elem.ty) {
        Some(places) => format_decimal(&text, places),
        None if value.is_number() && !text.chars().all(|c| c.is_ascii_digit()) => {
            Err(format!("expected a code, got the number {text}"))
        }
        None => Ok(text),
    }
}

fn format_decimal(text: &str, places: usize) -> Result<String, String> {
    let (int, frac) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if int.is_empty() || !digits(int) || !digits(frac) {
        return Err(format!("{text} is not a decimal number"));
    }
    if frac.len() > places {
        return Err(format!("{text} has more than {places} decimal places"));
    }
    Ok(format!("{int}.{frac:0<places$}"))
}

/// Serializes the content of `elem` in schema order, as canonical XML
/// (no whitespace, start/end tag pairs, C14N escaping).
pub fn write_children(
    out: &mut String,
    value: &Map<String, Value>,
    elem: &Elem,
) -> Result<(), String> {
    for child in elem.children() {
        let Some(v) = value.get(&child.name) else {
            continue;
        };
        match v {
            Value::Array(values) => {
                for v in values {
                    write_elem(out, v, child)?;
                }
            }
            v => write_elem(out, v, child)?,
        }
    }
    Ok(())
}

fn write_elem(out: &mut String, value: &Value, elem: &Elem) -> Result<(), String> {
    out.push('<');
    out.push_str(&elem.name);
    out.push('>');
    if elem.is_leaf() {
        out.push_str(&escape_text(
            &leaf_text(value, elem).map_err(|e| format!("{}: {e}", elem.name))?,
        ));
    } else if let Value::Object(map) = value {
        write_children(out, map, elem)?;
    } else {
        return Err(format!("{}: an object is expected", elem.name));
    }
    out.push_str("</");
    out.push_str(&elem.name);
    out.push('>');
    Ok(())
}

/// Text escaping as Canonical XML 1.0 does it.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MINI: &str = "
root 1 1 T
  a 1 1 TSDec15V2
  b 0 1 TX
    (choice)
      c 1 1 TS
      d 1 1 TS
    e 0 1 TS
  f 0 3 TS
";

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn parses_nested_elements_and_choices() {
        let root = parse(MINI).unwrap();
        assert_eq!(root.name, "root");
        let b = root.child("b").unwrap();
        assert_eq!(
            b.children().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["c", "d", "e"]
        );
        assert_eq!(b.choice_siblings("c"), ["d"]);
        assert!(root.child("f").unwrap().repeats());
    }

    #[test]
    fn real_schema_has_the_dps_groups() {
        let inf = inf_dps(Environment::Production);
        for name in ["tpAmb", "prest", "toma", "serv", "valores", "IBSCBS"] {
            assert!(inf.child(name).is_some(), "{name}");
        }
        let toma = inf.child("toma").unwrap();
        assert_eq!(toma.choice_siblings("cNaoNIF"), ["CNPJ", "CPF", "NIF"]);
    }

    #[test]
    fn staging_has_fin_nfse_at_the_root_and_production_in_ibscbs() {
        let staging = inf_dps(Environment::Staging);
        let names: Vec<&str> = staging.children().map(|e| e.name.as_str()).collect();
        let pos = |n: &str| names.iter().position(|x| *x == n).unwrap();
        assert!(
            pos("tpEmit") < pos("finNFSe") && pos("finNFSe") < pos("cLocEmi"),
            "{names:?}"
        );
        assert!(staging.child("IBSCBS").unwrap().child("finNFSe").is_none());
        assert!(
            pos("toma") < pos("indDest") && pos("indDest") < pos("serv"),
            "{names:?}"
        );
        let production = inf_dps(Environment::Production);
        assert!(production.child("finNFSe").is_none());
        assert!(
            production
                .child("IBSCBS")
                .unwrap()
                .child("finNFSe")
                .is_some()
        );
    }

    #[test]
    fn optional_choice_may_be_empty() {
        let root = parse("r 1 1 T\n  (choice?)\n    a 1 1 TS\n    b 1 1 TS\n").unwrap();
        assert!(validate(&Map::new(), &root, "").is_empty());
    }

    #[test]
    fn validate_reports_missing_unknown_and_choice_errors() {
        let root = parse(MINI).unwrap();
        let errors = validate(
            &obj(json!({"b": {"c": "1", "d": "2"}, "zzz": 1})),
            &root,
            "",
        );
        assert!(
            errors.contains(&"zzz: unknown field".to_string()),
            "{errors:?}"
        );
        assert!(errors.contains(&"a: required".to_string()), "{errors:?}");
        assert!(
            errors.iter().any(|e| e.contains("only one of c|d")),
            "{errors:?}"
        );
        let errors = validate(&obj(json!({"a": 1, "b": {}})), &root, "");
        assert_eq!(errors, ["b.*: one of c|d is required"]);
        assert!(
            validate(
                &obj(json!({"a": 1, "b": {"d": "x"}, "f": ["1", "2"]})),
                &root,
                ""
            )
            .is_empty()
        );
    }

    #[test]
    fn decimals_are_normalized() {
        let root = parse(MINI).unwrap();
        let a = root.child("a").unwrap();
        assert_eq!(leaf_text(&json!(1000), a).unwrap(), "1000.00");
        assert_eq!(leaf_text(&json!("1234.5"), a).unwrap(), "1234.50");
        assert!(leaf_text(&json!("1.234"), a).is_err());
        assert!(leaf_text(&json!("1,23"), a).is_err());
        let c = root.child("b").unwrap().child("c").unwrap();
        assert_eq!(leaf_text(&json!(1), c).unwrap(), "1");
        assert!(leaf_text(&json!(1.5), c).is_err());
    }

    #[test]
    fn merge_overrides_removes_nulls_and_switches_choices() {
        let root = parse(MINI).unwrap();
        let mut base = obj(json!({"a": "1.00", "b": {"c": "x", "e": "y"}, "f": ["1"]}));
        merge(
            &mut base,
            &obj(json!({"a": 2, "b": {"d": "z"}, "f": null})),
            &root,
        );
        assert_eq!(
            Value::Object(base),
            json!({"a": 2, "b": {"d": "z", "e": "y"}})
        );
    }

    #[test]
    fn writes_in_schema_order_with_escaping() {
        let root = parse(MINI).unwrap();
        let mut out = String::new();
        write_children(
            &mut out,
            &obj(json!({"f": ["1", "2"], "b": {"e": "A&B <x>", "c": "c"}, "a": 5})),
            &root,
        )
        .unwrap();
        assert_eq!(
            out,
            "<a>5.00</a><b><c>c</c><e>A&amp;B &lt;x&gt;</e></b><f>1</f><f>2</f>"
        );
    }
}
