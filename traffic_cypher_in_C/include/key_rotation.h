#ifndef KEY_ROTATION_H
#define KEY_ROTATION_H

#include <stdint.h>
#include "web_server.h"

/*
 * Start the entropy collection daemon in a background thread.
 * Runs every 1 second, collecting OS entropy and updating state.
 * state->rotation_stop should be set to 1 to signal shutdown.
 */
void *rotation_daemon(void *arg);

#endif
