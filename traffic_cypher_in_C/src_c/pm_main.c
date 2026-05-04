/*
 * Traffic Cypher Password Manager — Web UI
 *
 * Starts an HTTP server on 127.0.0.1:9876 serving the password manager
 * dashboard with the liquid glass UI.
 */

#include "web_server.h"

#include <stdio.h>

int main(void) {
    printf("\n"
        "+==========================================================+\n"
        "|                                                          |\n"
        "|     T R A F F I C   C Y P H E R                         |\n"
        "|   Entropy-Driven Password Manager                        |\n"
        "|                                                          |\n"
        "|   Dashboard: http://127.0.0.1:9876                       |\n"
        "|                                                          |\n"
        "+==========================================================+\n"
        "\n");

    app_state_t state;
    app_state_init(&state);

    return web_server_start(&state, 9876);
}
