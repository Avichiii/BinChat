#ifndef UTILS_H
#define UTILS_H

#include "libraries.h"
#include "crypto.h"


// Sends all bytes from a buffer to a socket, ensuring complete transmission
// Parameters:
//   socket - The target socket file descriptor
//   buf    - Pointer to the data buffer to send
//   size   - Number of bytes to send from the buffer
// Returns:
//   Number of bytes sent on success, or EXIT_FAILED on failure
int send_all(int socket, unsigned char *buf, size_t size);

// Receives a specific number of bytes from a socket, ensuring complete reception
// Parameters:
//   socket - The source socket file descriptor
//   buf    - Pointer to the buffer to store received data
//   size   - Number of bytes to receive
// Returns:
//   Number of bytes received on success, or EXIT_FAILED on failure
int recv_all(int socket, unsigned char *buf, size_t size);

// Sends an encrypted session key struct over a socket
// Parameters:
//   socket - The target socket file descriptor
//   encrypted_session_struct - Struct containing session key and its length
// Returns:
//   EXIT_SUCCESS on success, or EXIT_FAILED on failure
ssize_t send_struct_all(int socket, enc_session_key encrypted_session_struct);

// Receives an encrypted session key struct from a socket
// Parameters:
//   socket - The source socket file descriptor
//   encrypted_session_struct - Struct to hold received data (length and encrypted key)
// Returns:
//   The filled struct on success, or an empty struct (length 0, key NULL) on failure
enc_session_key recv_struct_all(int socket, enc_session_key encrypted_session_struct);

// Cleans up allocated server-side resources to prevent memory leaks
// Parameters:
//   client_socket - Client socket to close (if open)
//   pub_fp        - File pointer for public key file to close
//   client_pkt    - Pointer to client initial packet buffer to free
//   pub_key       - Pointer to public key buffer to free
//   enc_s_key     - Pointer to encrypted session key buffer to free
void cleanup_server_resources(int client_socket, FILE *pub_fp, unsigned char *client_pkt, unsigned char *pub_key,
                              unsigned char *enc_s_key);

// Cleans up client-side resources to prevent memory leaks
// Parameters:
//   socket        - Client socket to close (if open)
//   public_key    - Pointer to public key buffer to free
//   s_key         - Pointer to session key buffer to free
//   init_ack_pkt  - Pointer to initial ACK packet buffer to free
void cleanup_client_resources(int socket, unsigned char *public_key, unsigned char *s_key, unsigned char *init_ack_pkt);

// Cleans up cryptographic resources including files, buffers, RSA keys, and BIO structures
// Parameters:
//   fptr        - File pointer to close
//   pub_key     - Pointer to public key buffer to free
//   s_key       - Pointer to session key buffer to free
//   public_key  - RSA public key to free
//   privet_key  - RSA private key to free
//   bio_wrapper - BIO object to free
void cleanup_crypto_resources(FILE *fptr, unsigned char *pub_key, unsigned char *s_key, RSA *public_key, RSA *privet_key, BIO *bio_wrapper);

#endif