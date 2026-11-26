//! The element trees in src/schema/ are what tools/xsd2schema.py generates
//! from the XSDs in xsd/.

use std::process::Command;

#[test]
fn schema_files_match_the_xsds() {
    let root = env!("CARGO_MANIFEST_DIR");
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipped: python3 not installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for env in ["production", "staging"] {
        let out = dir.path().join(format!("{env}.txt"));
        let status = Command::new("python3")
            .arg("-I")
            .arg(format!("{root}/tools/xsd2schema.py"))
            .arg(format!("{root}/xsd/{env}"))
            .arg(&out)
            .status()
            .unwrap();
        assert!(status.success());
        let expected = std::fs::read_to_string(format!("{root}/src/schema/{env}.txt")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            expected,
            "regenerate src/schema/{env}.txt"
        );
    }
}
