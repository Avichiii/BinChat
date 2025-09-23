#include "server.h"
#include "libraries.h"
#include "crypto.h"
#include "main.h"
#include "globals.h"

// send_all() & recv_all() returns ssize_t which is signed type. this is usefull because we can also return error codes (-1)

// Regular send() may send fewer bytes than requested, especially on large data or non-blocking sockets. send_all ensures that all bytes are transmitted, providing reliable sending of complete messages.
ssize_t send_all(int socket, unsigned char *buf, size_t length) {
    size_t total = 0;               // Total bytes sent so far
    unsigned char *ptr = buf;       // Pointer to current position in buffer

    while (total < length) {
        ssize_t sent = send(socket, ptr + total, length - total, 0); // Attempt to send remaining bytes
        if (sent <= 0) {            // 0 = connection closed, -1 = error
            return sent;
        }
        total += sent;              // Update total bytes sent
    }

    return (ssize_t) total;         // Return total bytes sent 
}

// Regular recv() might return fewer bytes than requested, especially for large messages or network buffering. recv_all ensures that the entire message is received, making it safer for fixed-length protocol messages.
ssize_t recv_all(int socket, unsigned char *buf, size_t length) {
    size_t total = 0;                   // Total bytes received so far
    unsigned char *ptr = buf;           // Pointer to current position in buffer

    while (total < length) {
        ssize_t recved = recv(socket, ptr + total, length - total, 0); // Attempt to receive remaining bytes
        if (recved <= 0) {              // 0 = connection closed, -1 = error
            return recved;
        }
        total += recved;                // Update total bytes received
    }

    return (ssize_t) total;              // Return total bytes received
}

// Function to send the enc_session_key struct (length + encrypted key) over the socket
ssize_t send_struct_all(int socket, enc_session_key encrypted_session_struct) {
    // The size of the length field (always 4 bytes for an int)
    int enc_s_key_size = sizeof(encrypted_session_struct.length);  
    
    // Convert length of the encrypted session key to network byte order (for portability)
    int length_encrypted_session_key = htonl(encrypted_session_struct.length); 
    
    // Pointer to the actual encrypted session key bytes
    unsigned char *encrypted_s_key = encrypted_session_struct.encrypted_s_key; 
    
    // Validate pointer before using
    if(encrypted_s_key == NULL) {
        fprintf(stderr, "ERROR: encryped_s_key ptr is NULL [%s]\n", strerror(errno));
        return EXIT_FAILED;
    }

    // Step 1: Send the length of the encrypted session key (4 bytes)
    ssize_t bytes_send_length = send_all(socket, (unsigned char *)&length_encrypted_session_key, enc_s_key_size);
    
    // Step 2: Send the actual encrypted session key (binary data of specified length)
    ssize_t bytes_send_key = send_all(socket, encrypted_s_key, length_encrypted_session_key);

    // Check if either send failed
    if (bytes_send_key <= 0 || bytes_send_length <= 0) {
        int saved_errno = errno;
        fprintf(stderr, "ERROR: Couldn't send the struct to server [%s]\n", strerror(saved_errno));
        return EXIT_FAILED;
    }

    return EXIT_SUCCESS; // Success
}


// Function to receive the enc_session_key struct (length + encrypted key) from the socket
enc_session_key recv_struct_all(int socket, enc_session_key encrypted_session_struct) {
    // Create an empty return value in case of failure
    enc_session_key empty = {0, NULL};

    // The size of the length field (always 4 bytes for an int)
    int enc_s_key_size = sizeof(encrypted_session_struct.length);  
    
    // Temporary variable to hold the received length (in network byte order)
    int length_encrypted_session_key = 0;
    
    // Step 1: Receive the 4-byte length field
    ssize_t bytes_recved = recv_all(socket, (unsigned char *)&length_encrypted_session_key, enc_s_key_size);
    if (bytes_recved <= 0) {
        fprintf(stderr, "ERROR: Unable to receive %d bytes from client, bytes received %zd\n",
                sizeof(encrypted_session_struct.length), bytes_recved);
        return empty; // Return empty struct if failed
    }

    // Convert the received length from network byte order to host byte order
    encrypted_session_struct.length = ntohl(length_encrypted_session_key);
    
    // Allocate memory for the encrypted session key based on the received length
    encrypted_session_struct.encrypted_s_key = (unsigned char *) malloc(length_encrypted_session_key);
    if (!encrypted_session_struct.encrypted_s_key)
        return empty;
    
    // Step 2: Receive the actual encrypted session key data
    bytes_recved = recv_all(socket, encrypted_session_struct.encrypted_s_key, length_encrypted_session_key);
    if (bytes_recved <= 0) {
        fprintf(stderr, "ERROR: Unable to receive %d bytes from client, bytes received %zd\n",
                enc_s_key_size, bytes_recved);
        return empty; // Return empty struct if failed
    }

    return encrypted_session_struct; // Successfully received struct
}


void cleanup_server_resources(int client_socket, FILE *pub_fp, unsigned char *client_pkt, unsigned char *pub_key,
unsigned char *enc_s_key) {
    if (client_socket) close(client_socket);
    if (pub_fp) fclose(pub_fp);
    if (client_pkt) free(client_pkt);
    if (pub_key) free(pub_key);
    if (enc_s_key) free(enc_s_key);
}

void cleanup_client_resources(int socket, unsigned char *public_key, unsigned char *s_key, unsigned char *init_ack_pkt){
    if (socket >= 0) close(socket);
    if (public_key) {free(public_key); public_key = NULL;}
    if (s_key) {free(s_key); s_key = NULL;}
    if(init_ack_pkt) {free(init_ack_pkt); init_ack_pkt = NULL;}
}

void cleanup_crypto_resources(FILE *fptr, unsigned char *pub_key, unsigned char *s_key, RSA *public_key, RSA *privet_key, BIO *bio_wrapper) {
    if (fptr) fclose(fptr);
    if (pub_key) free(pub_key);
    if (s_key) free(s_key);
    if (privet_key) RSA_free(privet_key);
    if (public_key) RSA_free(public_key);
    if (bio_wrapper) BIO_free(bio_wrapper);
}