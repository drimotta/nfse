# XSD sources

| Folder | Package | Official URL | sha256 of the zip |
|---|---|---|---|
| `production/` | esquemas-xsd-v1.01-20260209 | https://www.gov.br/nfse/pt-br/biblioteca/documentacao-tecnica/documentacao-atual/esquemas-xsd-v1.01-20260209.zip | e7935cbd9470527c6cc32984c1b2263e614183bf0139ce2733eaaed2de9a8072 |
| `staging/` | esquemas-xsd-producao-restrita-20261124 (NT 009) | https://www.gov.br/nfse/pt-br/biblioteca/documentacao-tecnica/producao-restrita/esquemas-xsd-producao-restrita-20261124.zip | 1ca83c1a7929f6d5684c9a17700fe3d3a375e4ea12b7ccb832bfc369768902c0 |

Copied from the mirror at https://github.com/stackin-io/data-source (data/nfse),
which tracks the gov.br documentation page. Check the hashes against a direct
download from gov.br when possible.

After replacing a folder, regenerate its tree:
`tools/xsd2schema.py xsd/<env> src/schema/<env>.txt`.
