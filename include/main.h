#ifndef MAIN_H
#define MAIN_H

#include "libraries.h"
#include "server.h"

// Macro defining the return value for a failed operation
// Commonly used throughout the client and server code to indicate an error
#define EXIT_FAILED -1

// Maximum size of the buffer used for sending and receiving messages
// Ensures that messages do not exceed this limit for both encryption/decryption
#define BUFFER_SIZE 2048


#endif