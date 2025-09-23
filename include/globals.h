#ifndef GLOBALS_H
#define GLOBALS_H

#include "libraries.h"
#include "server.h"

// Array of predefined packets used for client-server handshake or initialization
// Each element points to a null-terminated string representing a specific handshake packet
extern char *packets[];

// Path to the server's private RSA key file
// Used for decrypting client session keys or signing messages
extern char *PATH_TO_PRIVET_KEY;

// Path to the server's public RSA key file
// Used for sending to clients during session establishment for encryption
extern char *PATH_TO_PUBLIC_KEY;

// Array holding information about all connected clients
// Each element is a 'client' struct containing socket, name, and session key
extern client client_struct_array[];

// Counter tracking the number of currently active clients in 'client_struct_array'
// Updated when clients connect or disconnect
extern size_t client_struct_counter;

// Counter tracking the total number of concurrent connections handled by the server
// Used to enforce CONNECTION_LIMIT and manage new incoming clients
extern size_t connection_counter;


#endif
