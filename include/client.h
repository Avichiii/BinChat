#ifndef CLIENT_H
#define CLIENT_H

#include "libraries.h"

// Struct used to share data about a connected client between threads
typedef struct shared_client_data {
    int client_socket;       // The socket file descriptor associated with the client
    volatile int running;    // Flag indicating if the client connection is active (volatile ensures thread-safe access)
} client_data;


// Struct representing a client's session information
typedef struct client_session {
    char *name;              // Pointer to the client's chosen display name (dynamically allocated)
    unsigned char *s_key;    // Pointer to the symmetric session key used for encrypting communication
} client_s;


#endif