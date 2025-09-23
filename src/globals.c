#include "libraries.h"
#include "globals.h"
#include "server.h"

// Array of predefined handshake and data packets used in client-server communication
// Each string represents a specific stage or action in the chat protocol
char *packets[] = {
    "init_pkt",         // Initial handshake packet sent by client to server
    "init_ack_pkt",     // Acknowledgment from server confirming handshake
};

// Absolute path to the server's private RSA key file
// Used for decrypting incoming session keys and signing messages securely
char *PATH_TO_PRIVET_KEY = "key_rsa";

// Absolute path to the server's public RSA key file
// Sent to clients during session initialization to encrypt session keys
char *PATH_TO_PUBLIC_KEY = "key_rsa.pem";

// Array holding information about currently connected clients
// Each element contains the client's socket, name, and encryption session key
client client_struct_array[CONNECTION_LIMIT]; 

// Counter tracking the number of active clients currently stored in client_struct_array
size_t client_struct_counter = 0;

// Counter tracking the total number of concurrent connections being handled
// Used to enforce CONNECTION_LIMIT and manage new incoming clients
size_t connection_counter = 0;
