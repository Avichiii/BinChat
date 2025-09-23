#ifndef SERVER_H
#define SERVER_H

#include <stddef.h>

// Maximum number of simultaneous client connections the server will accept
#define CONNECTION_LIMIT 300


// Struct representing a connected client on the server side
typedef struct clients_connection_data_structure {
    unsigned char *session_key;  // Pointer to the symmetric session key for encrypting communication with this client
    int client_sock;             // Socket file descriptor for this client
    char *client_name;           // Pointer to the client's chosen display name (dynamically allocated)
} client;

#endif