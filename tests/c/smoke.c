/* Calls the library through include/nfse.h, the way the agent and the
 * server do, so the header and the exported symbols stay in step. */
#include "nfse.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...)                         \
    do {                                         \
        if (!(cond)) {                           \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);        \
            fputc('\n', stderr);                 \
            failures++;                          \
        }                                        \
    } while (0)

int main(void) {
    CHECK(strlen(nfse_version()) > 0, "empty version");

    char *response = NULL;
    int rc = nfse_build_dps("{\"environment\":\"staging\"}", &response);
    CHECK(rc == NFSE_ERR_INPUT, "build without numbers: %d", rc);
    CHECK(response && strstr(response, "\"code\":\"input\""), "response: %s", response);
    nfse_free(response);

    response = NULL;
    rc = nfse_list_certificates("{\"module\":\"/nonexistent.so\"}", &response);
    CHECK(rc == NFSE_ERR_TOKEN, "missing module: %d", rc);
    nfse_free(response);

    nfse_session *session = (nfse_session *)1;
    response = NULL;
    rc = nfse_session_open("{\"module\":\"/nonexistent.so\",\"pin\":\"1\"}", &session, &response);
    CHECK(rc == NFSE_ERR_TOKEN, "open: %d", rc);
    CHECK(session == NULL, "session left set");
    nfse_free(response);

    response = NULL;
    rc = nfse_sign_dps(NULL, "{}", &response);
    CHECK(rc == NFSE_ERR_INPUT, "sign without a session: %d", rc);
    nfse_free(response);

    nfse_session_close(NULL);
    nfse_free(NULL);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("C API smoke test passed");
    return 0;
}
