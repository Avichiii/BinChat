#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define SESSION_KEY_LENGTH 16   // Length of the AES session key in bytes (16 bytes = 128 bits)
#define RC4_STATE_SIZE 256      // Size of RC4 internal state array (S-box), always 256




// Structure to hold the encrypted session key and its length
typedef struct encrypted_session_key_and_length {
    int length;                 // Length of encrypted session key in bytes
    unsigned char *encrypted_s_key;  // Pointer to encrypted session key
} enc_session_key;

char *rc4(unsigned char *s_key, char *data, size_t data_length); // RC4 encryption/decryption function
void swap(unsigned char S[], size_t i, size_t j);               // Helper to swap two bytes in array

unsigned char *session_key();                        // Generates a random session key
enc_session_key encrypt(unsigned char *s_key, unsigned char *pub_key);       // Encrypts session key using RSA public key
unsigned char *decrypt(enc_session_key encrypted_session_key); // Decrypts encrypted session key using RSA private key

#endif