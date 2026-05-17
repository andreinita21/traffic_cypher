/*
 * Traffic Cypher Password Manager — Web UI
 *
 * Starts an HTTP server serving the password manager dashboard.
 * Bind address/port default to 127.0.0.1:9876; override with the
 * TC_BIND_ADDR (see web_server.c) and TC_PORT environment variables.
 */

#include "web_server.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* Port is configurable via TC_PORT for multi-instance / tunnel
     * deployments; the bind address via TC_BIND_ADDR (handled in
     * web_server.c). Defaults keep the documented 127.0.0.1:9876 behaviour. */
    int port = 9876;
    const char *port_env = getenv("TC_PORT");
    if (port_env && *port_env) {
        int p = atoi(port_env);
        if (p > 0 && p < 65536) {
            port = p;
        } else {
            fprintf(stderr, "[WARN] ignoring invalid TC_PORT=%s\n", port_env);
        }
    }

    const char *bind_addr = getenv("TC_BIND_ADDR");
    if (!bind_addr || !*bind_addr) bind_addr = "127.0.0.1";

    printf("\n"
        "+==========================================================+\n"
        "|                                                          |\n"
        "|     T R A F F I C   C Y P H E R                         |\n"
        "|   Entropy-Driven Password Manager                        |\n"
        "|                                                          |\n"
        "+==========================================================+\n");
    printf("   Dashboard: http://%s:%d\n\n", bind_addr, port);

    app_state_t state;
    app_state_init(&state);

    return web_server_start(&state, port);
}
