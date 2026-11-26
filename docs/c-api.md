# C API

`include/nfse.h` exposes the library to C (the Cascalho agent) and to any
language with a C FFI (the Cascalho server, in Ruby). Build it with
`cargo build --release`: `target/release/libnfse.so` (`.dylib` on macOS) and
`libnfse.a`.

Every call takes a JSON object and writes a JSON response that the caller
frees with `nfse_free()`. The return value is the status:

| Code | Name | `error.code` | Meaning |
| --- | --- | --- | --- |
| 0 | `NFSE_OK` | | Success |
| 1 | `NFSE_ERR_INPUT` | `input` | Malformed request or invalid DPS content |
| 2 | `NFSE_ERR_TOKEN` | `token` | Module, token or key cannot be used |
| 3 | `NFSE_ERR_PIN` | `pin` | Wrong PIN |
| 4 | `NFSE_ERR_PIN_LOCKED` | `pin_locked` | PIN blocked |
| 5 | `NFSE_ERR_REJECTED` | `rejected` | The RFB rejected the DPS; `messages` lists why |
| 6 | `NFSE_ERR_UNKNOWN_OUTCOME` | `unknown_outcome` | Look the DPS id up before sending anything again |
| 7 | `NFSE_ERR_NETWORK` | `network` | A lookup or download failed |
| 99 | `NFSE_ERR_INTERNAL` | `internal` | A bug |

An error response is `{"error": {"code": "...", "message": "..."}}`.

## Building (no token)

`nfse_build_dps`

```json
{
  "environment": "staging",
  "serie": "1",
  "n_dps": "42",
  "emitted_at": "2026-11-26T10:05:09-03:00",
  "reuse_xml": "<optional earlier NFS-e or DPS XML>",
  "content": { "dCompet": "2026-11-01", "...": "the DPS fields, as the CLI input" }
}
```

`serie` (1 to 5 digits) and `n_dps` (1 to 15 digits, no leading zero) are
the caller's: the server keeps one counter per issuer and series and never
reuses a number. `emitted_at` defaults to now. `content` overrides
`reuse_xml` field by field. The generated fields (`tpAmb`, `dhEmi`,
`verAplic`, `serie`, `nDPS`) cannot be in `content`.

Response: `{"id": "DPS...", "xml": "<unsigned DPS>"}`.

## Token (agent)

`nfse_list_certificates`: `{"module": "/path/to/opensc-pkcs11.so"}` returns
the tokens and the certificates they show before login:

```json
{"tokens": [{"label": "...", "serial": "...", "certificates": [
  {"id": "a1dfc937", "label": "...", "der_b64": "...", "subject": "...",
   "not_after": "2027-03-01T12:00:00+00:00", "usable": true}]}]}
```

`usable` means: not a CA, in date, allowed to sign and to authenticate a TLS
client.

`nfse_session_open`: `{"module": "...", "pin": "...", "token_label": "...",
"key_id": "a1dfc937", "key_label": "..."}` (the last three optional) logs in
and returns `{"certificate_b64": "..."}`. Close the session before listing
again: one module is initialised once per process.

`nfse_sign_dps`: `{"xml": "<unsigned DPS>"}` returns `{"id", "xml"}`, the
signed DPS. Only a DPS exactly as `nfse_build_dps` writes it is signed.

`nfse_sign_challenge`: `{"challenge_b64": "..."}` (16 to 1024 bytes) returns
`{"signature_b64", "certificate_b64", "algorithm": "rsa-pkcs1-sha256",
"prefix": "NFSE-LOGIN-V1\n"}`. The signature covers the prefix followed by
the challenge bytes; verify it over the same bytes.

## RFB (agent)

`nfse_submit`:

```json
{"environment": "staging", "signed_xml": "...", "dps_id": "DPS...",
 "sefin_url": "optional", "adn_url": "optional", "ca_bundle": "optional PEM path",
 "recovery_delays_ms": [2000, 5000, 10000]}
```

returns `{"chave_acesso", "nfse_xml"}`. On an uncertain outcome the DPS id is
looked up after each delay and the same bytes are sent once more if still
unknown; after that the result is `NFSE_ERR_UNKNOWN_OUTCOME`.

`nfse_fetch_danfe`: the same connection fields plus `"chave_acesso"` return
`{"pdf_b64": "..."}`.

## Tests

`cargo test` covers the behaviour (SoftHSM stands in for the card) and
`make c-test` compiles `tests/c/smoke.c` against the header.
