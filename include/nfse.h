/*
 * nfse: build, sign and submit NFS-e Nacional DPS documents.
 *
 * Every call takes a JSON request (UTF-8, NUL-terminated) and writes a JSON
 * response to *response, which the caller releases with nfse_free(). The
 * return value is NFSE_OK or one of the NFSE_ERR_* codes; on an error the
 * response is {"error": {"code": "<name>", "message": "<text>"}}, plus
 * "messages" (the RFB's list) for NFSE_ERR_REJECTED.
 *
 * Requests and responses are documented in docs/c-api.md.
 */
#ifndef NFSE_H
#define NFSE_H

#ifdef __cplusplus
extern "C" {
#endif

#define NFSE_OK 0
/* The request is malformed or the DPS content is invalid. */
#define NFSE_ERR_INPUT 1
/* The PKCS#11 module, token or key cannot be used. */
#define NFSE_ERR_TOKEN 2
/* Wrong PIN. */
#define NFSE_ERR_PIN 3
/* The PIN is blocked. */
#define NFSE_ERR_PIN_LOCKED 4
/* The RFB rejected the DPS; fix it and send it as a new DPS. */
#define NFSE_ERR_REJECTED 5
/* The outcome of a submission is unknown: never send the DPS again with a
 * new number before looking its id up. */
#define NFSE_ERR_UNKNOWN_OUTCOME 6
/* A request to the RFB failed (lookups and downloads, not submissions). */
#define NFSE_ERR_NETWORK 7
#define NFSE_ERR_INTERNAL 99

/* A logged-in token session with the chosen key. */
typedef struct nfse_session nfse_session;

/* The library version, a static string. */
const char *nfse_version(void);

/* Builds an unsigned DPS. Needs no token. */
int nfse_build_dps(const char *request, char **response);

/* Lists the tokens of a PKCS#11 module and their certificates, without a
 * PIN. */
int nfse_list_certificates(const char *request, char **response);

/* Opens a session: picks the token and key and logs in. On success
 * *session is set; close it with nfse_session_close(). */
int nfse_session_open(const char *request, nfse_session **session, char **response);

/* Signs an unsigned DPS built by nfse_build_dps(). */
int nfse_sign_dps(nfse_session *session, const char *request, char **response);

/* Signs a login challenge. The signed bytes are the prefix
 * "NFSE-LOGIN-V1\n" followed by the challenge, so a challenge can never be
 * a document signature. */
int nfse_sign_challenge(nfse_session *session, const char *request, char **response);

/* Submits a signed DPS over mutual TLS with the session's key. */
int nfse_submit(nfse_session *session, const char *request, char **response);

/* Downloads the DANFSe PDF of an issued NFS-e. */
int nfse_fetch_danfe(nfse_session *session, const char *request, char **response);

/* Logs out and releases the session. NULL is ignored. */
void nfse_session_close(nfse_session *session);

/* Releases a response. NULL is ignored. */
void nfse_free(char *response);

#ifdef __cplusplus
}
#endif

#endif /* NFSE_H */
