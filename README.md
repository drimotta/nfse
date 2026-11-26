# NFS CLI generation

## Quick start

```bash
$ nfse --production --submit < full.json
```

This generates a local statement of provided service (DPS) from an input JSON,
signs it with the A3 token through OpenSC and submits the document to RFB. If
successful, it outputs the resulting NFS-e XML to `stdout`.

A typical monthly run reuses last month's NFS-e and only changes the amounts:

```bash
$ echo '{"serv":{"comExt":{"vServMoeda":1000}},"valores":{"vServPrest":{"vServ":5500.00}}}' \
    | nfse --reuse last.xml --today --submit --xml-outfile --pdf-outfile
```

## Dependencies

### Rust

A stable toolchain, 1.85 or newer (edition 2024; `rustup update`). Build with `cargo build --release`;
the binary is `target/release/nfse`.

### OpenSSL 3 (build time)

TLS goes through OpenSSL 3, linked by the `openssl-sys` crate, which needs the
headers and `pkg-config` (or `OPENSSL_DIR`) when building.

- macOS: `brew install openssl@3 pkg-config`, then

    ```bash
    export OPENSSL_DIR="$(brew --prefix openssl@3)"
    ```

    Put it in your shell profile; the binary keeps that absolute library path.
- Debian/Ubuntu: `sudo apt install libssl-dev pkg-config` (found automatically).
- Fedora: `sudo dnf install openssl-devel pkgconf`.

Check: `openssl version` should say 3.x, and on macOS
`otool -L target/release/nfse | grep ssl` should point into `$OPENSSL_DIR/lib`.

### OpenSC (run time)

The token is used through OpenSC's PKCS#11 module, `opensc-pkcs11.so`, loaded
when the program runs (nothing is linked at build time).

- Packaged: `brew install opensc` (macOS) or `sudo apt install opensc pcscd`
    (Debian/Ubuntu; `pcscd` must be running).
- From a fork or a source checkout (e.g. a branch with card fixes):

    ```bash
    ./bootstrap && ./configure --prefix=/usr/local && make && sudo make install
    ```

    which installs `/usr/local/lib/opensc-pkcs11.so`. Install it to a private
    prefix instead (`--prefix=$HOME/opt/opensc`, no `sudo`) to keep it apart
    from a packaged OpenSC.

The module is looked up in the default paths listed under
[Environment](#environment), in that order. When it lives elsewhere, or both a
packaged and a source build are installed, point to it explicitly:

```bash
export NFSE_PKCS11_MODULE="$HOME/opt/opensc/lib/opensc-pkcs11.so"
```

Check that the card is seen and that the module is the one you expect:

```bash
pkcs11-tool --module "$NFSE_PKCS11_MODULE" -L   # slots and token label
pkcs11-tool --module "$NFSE_PKCS11_MODULE" -O   # certificates and keys (CKA_ID)
```

## Parameters

- `--staging` - uses the staging ("produção restrita") server. Enabled by default.
- `--production` - uses the production server, creating a real NFS.
- `--dry-run` - prints out the generated DPS, unsigned, and quits. The token is
    not used.
- `--submit` - actually submits the DPS and prints out the created NFS's XML.
    Without it, the signed DPS is printed.
- `--reuse nfs.xml` - reads `nfs.xml` (an NFS-e, or a DPS) and reuses its data
    (except for the DPS id). Its fields can be overridden by the input JSON.
- `--today` - sets the NFS date (`dCompet`) to today (overrides `--reuse` and
    the input file).
- `--xml-outfile` - saves the XML to a file instead of `stdout`. The file name
    is the DPS id.
- `--pdf-outfile` - saves the DANFSe PDF to a file (needs `--submit`). The file
    name is the DPS id.
- `--help` - prints this parameters list.

## Input

The input JSON is read from `stdin` and mirrors the `infDPS` element of the DPS
(layout 1.01): keys are the XSD element names, nested as in the XML. Order does
not matter; the XML is written in schema order. See
[`examples/input.json`](examples/input.json) for the export-of-services case.

- Every element the XSD requires must be present, unless `--reuse` provides it.
    All missing or unknown fields are reported at once.
- Decimal values may be numbers or strings (`1000` becomes `1000.00`). Codes
    with leading zeros (`"010101"`, `"01"`) must be strings.
- `null` removes a field taken from `--reuse`. Setting one option of a choice
    (e.g. `pTotTrib` instead of `vTotTrib`) replaces the other.
- `tpEmit` defaults to `1` (prestador).
- Fields that moved between the production and staging layouts (`finNFSe`,
    `indDest`, `dest`, `CST`, `cClassTrib`, `vServMoeda`/`vFatura`) are moved
    automatically, so an NFS-e from either
    environment can be reused in the other.
- The BRL value (`valores.vServPrest.vServ`) is always provided by you; it is not
    computed from the exchange rate.

### Export of services in staging (NT 009)

Staging applies the NT 009 rules (Anexo I of 2026-11-24). An export to a foreign
taker went through (cStat 100) with these overrides on top of a production NFS-e:

```json
{"prest": {"IM": "<IM as registered in staging>"},
 "IBSCBS": {"cIndOp": null,
            "valores": {"trib": {"CST": "410", "cClassTrib": "410004"}}}}
```

- `410004` (exports, LC 214 art. 8) is not taxed for IBS/CBS, so `cIndOp` and
    `gIBSCBS` are forbidden (E0859, E0961), and the taker needs no CPF/CNPJ
    or Brazilian address (E0243, E0239 apply to taxed operations only).
- With a taxed code (`000001`), `cIndOp` is required (E0860) and, with
    `indDest = 0`, E0243 rejects a foreign taker.
- The production layout of 2026-02-09 still requires `cIndOp`, so the example
    keeps the production form.
- Staging keeps its own CNC: the IM may differ from production (E0116).

Generated by the tool, and rejected in the input: `tpAmb`, `dhEmi` (now,
Brasília time), `verAplic`, `serie` (the year, `YYYY`) and `nDPS` (`MMDDHHmmSS`,
written without leading zeros as the schema requires). The DPS id is built from
them and never reused.

## Environment

| Variable | Use |
|---|---|
| `NFSE_PKCS11_MODULE` | PKCS#11 module. Default: the first that exists of `/opt/homebrew/lib`, `/usr/local/lib`, `/Library/OpenSC/lib` (macOS) or `/usr/lib/x86_64-linux-gnu`, `/usr/lib/aarch64-linux-gnu`, `/usr/lib64`, `/usr/lib`, `/usr/local/lib` (Linux), each with `opensc-pkcs11.so` |
| `NFSE_PIN` | Token PIN. Default: asked on the terminal |
| `NFSE_TOKEN_LABEL` | Token to use when more than one shows a certificate |
| `NFSE_KEY_ID` | CKA_ID (hex) of the key to use, when more than one key fits (the error lists them) |
| `NFSE_KEY_LABEL` | Label of the key to use |
| `NFSE_CA_BUNDLE` | PEM file with extra trusted roots, added to OpenSSL's default store |
| `NFSE_SEFIN_URL`, `NFSE_ADN_URL` | Base URL overrides (tests, municipal hosts) |

## How it works

- `src/cli.rs` - `main`: `initialize` (env, `--reuse`, input), `build_dps`,
    `sign_dps`, then `submit_dps` + `output_result` or `output_dps`.
- `src/dps.rs` - `build_dps` and `sign_dps`: XMLDSig enveloped, RSA-SHA256,
    inclusive C14N, `Reference` to `#<infDPS Id>`.
- `src/connector.rs` - `submit_dps`, `fetch_xml`, `fetch_danfe` (and
    `lookup_dps`).
- `src/schema.rs` + `src/schema/{production,staging}.txt` - the DPS element
    tree of each environment, used to validate, merge and serialize. Staging
    ("produção restrita") already runs a newer v1.01 XSD than production (e.g.
    `finNFSe` at the `infDPS` root, `CST`/`cClassTrib` directly under
    `IBSCBS.valores.trib`). The trees are generated from `xsd/<env>/` by
    `tools/xsd2schema.py xsd/<env> src/schema/<env>.txt`; when RFB publishes a
    new XSD package, replace the files in `xsd/` and regenerate (a test checks
    they are in sync). `xsd/SOURCES.md` lists the packages and their hashes.
- `src/pkcs11.rs` - the key on the token (`CKM_RSA_PKCS`; keys with
    `CKA_ALWAYS_AUTHENTICATE` are supported).
- `src/tls.rs` + `src/http.rs` - mutual TLS over OpenSSL with the token key
    (a custom RSA method that signs on the token). **TLS 1.2 only**: Sefin asks
    for the client certificate by renegotiating after it reads the request,
    which TLS 1.3 does not have, and TLS 1.3 would need RSA-PSS client
    signatures, which the ICP-Brasil Oberthur card does not offer.

If a submission's outcome is unknown (timeout, 5xx), the tool looks the DPS id
up instead of submitting a new DPS, and resends the same signed bytes at most
once. If it still cannot tell, it saves `<DPS id>-signed.xml` and stops: check
the DPS id before trying again.

## Tests

```bash
$ cargo test
```

The token, TLS and end-to-end tests use SoftHSM, OpenSC's `pkcs11-tool`,
`openssl` and `xmlsec1`, and are skipped when those are missing
(`apt install softhsm2 opensc xmlsec1` or `brew install softhsm opensc
libxmlsec1`). `libsofthsm2.so` is looked up in `/usr/lib/softhsm/` and the Homebrew
prefixes; set `SOFTHSM_MODULE` to use another path.

Test fixtures are synthetic. Do not add real NFS-e XMLs to the repository.

## Troubleshooting TLS

```bash
$ RUST_LOG=nfse=info nfse --reuse last.xml --submit
```

logs `signing the TLS handshake on the token` when the server asks for the
client certificate and the token signs it.
