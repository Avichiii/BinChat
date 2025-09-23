#include "crypto.h"
#include "libraries.h"
#include "utils.h"
#include "main.h"
#include "globals.h"

// Function prototypes
unsigned char *session_key();                                    // Generates a random session key
enc_session_key encrypt(unsigned char *s_key, unsigned char *pub_key); // Encrypts session key using RSA public key
unsigned char *decrypt(enc_session_key encrypted_session_key);   // Decrypts RSA-encrypted session key

char *rc4(unsigned char *s_key, char *data, size_t data_length);  // RC4 encryption/decryption
void swap(unsigned char S[], size_t i, size_t j);                // Helper function to swap two bytes in an array

// -------------------- Generate a random session key --------------------
unsigned char *session_key() {
    FILE *fptr = fopen("/dev/urandom", "r");   // Open the system's random source
    if (!fptr) {
        fprintf(stderr, "ERROR: Unable to open /dev/urandom: %s\n", strerror(errno));
        return NULL;
    }

    // Allocate memory for the session key
    unsigned char *session_key = (unsigned char *) malloc(SESSION_KEY_LENGTH);
    if (!session_key) {
        fprintf(stderr, "ERROR: Unable to allocate memory for session_key: %s\n", strerror(errno));
        cleanup_crypto_resources(fptr, NULL, NULL, NULL, NULL, NULL);
        return NULL;
    }

    // Read 16 random bytes from /dev/urandom into the session key
    size_t char_read = fread(session_key, 1, SESSION_KEY_LENGTH, fptr);
    if (char_read != SESSION_KEY_LENGTH) {
        fprintf(stderr, "ERROR: Failed to read full session key, only read %zu bytes\n", char_read);
        cleanup_crypto_resources(fptr, NULL, session_key, NULL, NULL, NULL);
        return NULL;
    }

    cleanup_crypto_resources(fptr, NULL, NULL, NULL, NULL, NULL);
    return session_key;   // Return the generated session key
}

// -------------------- Encrypt session key using RSA public key --------------------
enc_session_key encrypt(unsigned char *s_key, unsigned char *pub_key) {
    enc_session_key empty = {0, NULL};   // Empty struct to return if encryption fails
    unsigned char session_k[SESSION_KEY_LENGTH];

    // Copy the session key into a local fixed-size array
    for(size_t i = 0; i < SESSION_KEY_LENGTH; ++i) {
        session_k[i] = s_key[i];
    }

    int public_key_size = (int) strlen(pub_key);

    // Wrap an existing memory buffer (pub_key) into a BIO object
    // BIO acts like a generic I/O stream (can represent files, memory, sockets, etc.)
    // In this case, BIO_new_mem_buf makes OpenSSL treat 'pub_key' as if it were a file.
    // BIO *bio = BIO_new_mem_buf(pub_key, PUBLIC_KEY_SIZE);
    BIO *bio = BIO_new_mem_buf(pub_key, public_key_size);


    // Parse an RSA public key from the BIO (memory buffer).
    // PEM_read_bio_RSAPublicKey expects the PEM block "-----BEGIN RSA PUBLIC KEY-----"
    // If your key is in "-----BEGIN PUBLIC KEY-----" format (PKCS#8), 
    // you should instead use PEM_read_bio_PUBKEY.
    RSA *public_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);

    // Check if public key parsing failed
    if (!public_key) {
        fprintf(stderr, "ERROR: Unable to read RSA public key\n");
        ERR_print_errors_fp(stderr);   // Print OpenSSL-specific errors
        cleanup_crypto_resources(NULL, NULL, NULL, NULL, NULL, bio);
        return empty;
    }

    // Get modulus size of the RSA key (in bytes)
    int size_of_public_key = RSA_size(public_key);
    if (size_of_public_key < 128>) { 
        fprintf(stderr, "ERROR: RSA_size returned invalid public key size: %d bytes\n", size_of_public_key);
        cleanup_crypto_resources(NULL, NULL, NULL, public_key, NULL, bio);
        return empty;
    }

    // Allocate memory for the encrypted session key
    // Ciphertext size is always equal to the RSA modulus size
    unsigned char *encrypted_session_key = (unsigned char *) malloc(size_of_public_key);
    if (!encrypted_session_key) {
        fprintf(stderr, "ERROR: Unable to allocate memory for encrypted session key: [%s]\n", strerror(errno));
        cleanup_crypto_resources(NULL, NULL, NULL, public_key, NULL, bio);
        return empty;
    }

    // Encrypt the session key using RSA public key with OAEP padding
    int length_of_encrypted_key = RSA_public_encrypt(
        SESSION_KEY_LENGTH,       // Input length: 16 bytes
        session_k,                // Input: plaintext session key
        encrypted_session_key,    // Output: ciphertext
        public_key,               // RSA public key
        RSA_PKCS1_OAEP_PADDING    // OAEP padding for security
    );

    // Free temporary resources
    cleanup_crypto_resources(NULL, NULL, NULL, public_key, NULL, bio);

    // Check if encryption failed
    if (length_of_encrypted_key == -1) {
        fprintf(stderr, "ERROR: Failed to encrypt session key\n");
        ERR_print_errors_fp(stderr);
        cleanup_crypto_resources(NULL, NULL, encrypted_session_key, NULL, NULL, NULL);
        return empty;
    }

    // Populate the struct with encrypted session key and its length
    enc_session_key session_struct;
    session_struct.length = length_of_encrypted_key;
    session_struct.encrypted_s_key = encrypted_session_key;

    return session_struct;  // Return the encrypted session key
}

// -------------------- Decrypt RSA-encrypted session key --------------------
unsigned char *decrypt(enc_session_key encrypted_session_key) {
    int length_encrypted_session_key = encrypted_session_key.length;
    unsigned char *encrypted_s_key = encrypted_session_key.encrypted_s_key;

    // Check for invalid input
    if (length_encrypted_session_key <= 0 || encrypted_s_key == NULL) {
        fprintf(stderr, "ERROR: Invalid encrypted session key\n");
        return NULL;
    }
    
    // Open RSA private key file
    FILE *privet_key_file_ptr = fopen(PATH_TO_PRIVET_KEY, "r");
    if (!privet_key_file_ptr) {
        fprintf(stderr, "ERROR: Failed to load private key %s: %s\n", PATH_TO_PRIVET_KEY, strerror(errno));
        // cleanup_crypto_resources(NULL, NULL, encrypted_s_key, NULL, NULL, NULL);
         cleanup_crypto_resources(NULL, NULL, NULL, NULL, NULL, NULL);
        return NULL;
    }
    
    // Read the private key from file
    RSA *privet_key = PEM_read_RSAPrivateKey(privet_key_file_ptr, NULL, NULL, NULL);
    if (!privet_key) {
        fprintf(stderr, "ERROR: Unable to read RSA private key\n");
        ERR_print_errors_fp(stderr);
        cleanup_crypto_resources(privet_key_file_ptr, NULL, NULL, NULL, NULL, NULL);
        return NULL;
    }

    // Get RSA key size in bytes
    int length_of_privet_key = RSA_size(privet_key);
    // Check if ciphertext length matches key size
    if (length_encrypted_session_key != length_of_privet_key) {
        fprintf(stderr, "ERROR: Ciphertext length %d does not match RSA key size %d\n",
                length_encrypted_session_key, length_of_privet_key);
        cleanup_crypto_resources(privet_key_file_ptr, NULL, NULL, NULL, privet_key, NULL);
        return NULL;
    }

    // Allocate memory for decrypted session key
    unsigned char *decrypted_session_key = (unsigned char *) malloc(length_of_privet_key);
    if (!decrypted_session_key) {
        fprintf(stderr, "ERROR: Failed to allocate memory for decrypted session key: [%s]\n", strerror(errno));
        cleanup_crypto_resources(privet_key_file_ptr, NULL, NULL, NULL, privet_key, NULL);
        return NULL;
    }

    // Perform RSA decryption using private key and OAEP padding
    int length_of_decrypted_session_key = RSA_private_decrypt(
        length_encrypted_session_key,  // Ciphertext length
        encrypted_s_key,               // Ciphertext input
        decrypted_session_key,         // Output buffer
        privet_key,                    // RSA private key
        RSA_PKCS1_OAEP_PADDING         // Padding scheme
    );

    // Free resources used for encrypted key and RSA structures
    cleanup_crypto_resources(privet_key_file_ptr, NULL, NULL, NULL, privet_key, NULL);

    // Check if decryption failed
    if (length_of_decrypted_session_key == -1) {
        fprintf(stderr, "ERROR: Failed to decrypt session key\n");
        ERR_print_errors_fp(stderr);
        cleanup_crypto_resources(NULL, NULL, decrypted_session_key, NULL, NULL, NULL);
        return NULL;
    }

    return decrypted_session_key;  // Return the decrypted session key
}


// -------------------- RC4 Encryption / Decryption --------------------

// Helper function to swap two elements in the S-box
void swap(unsigned char S[], size_t i, size_t j){
    unsigned char temp = S[i];
    S[i] = S[j];
    S[j] = temp;
}

// RC4 encryption/decryption function
// RC4 is symmetric: same function can encrypt and decrypt
char *rc4(unsigned char *s_key, char *data, size_t data_length) {
    // -------------------------------
    // Step 1: Initialize State Array
    // -------------------------------
    unsigned char S[RC4_STATE_SIZE];  // State array (S-box)
    for (size_t i = 0; i < RC4_STATE_SIZE; ++i) {
        S[i] = i;  // Identity permutation: 0,1,2,...,255
    }

    // -------------------------------
    // Step 2: Key Scheduling Algorithm (KSA)
    // -------------------------------
    size_t i, j = 0;
    for(i = 0; i < RC4_STATE_SIZE; ++i) {
        // Shuffle S based on session key
        j = (j + S[i] + s_key[i % SESSION_KEY_LENGTH]) % RC4_STATE_SIZE;
        swap(S, i, j);  // Swap S[i] and S[j]
    }

    // -------------------------------
    // Step 3: Pseudo-Random Generation Algorithm (PRGA)
    // -------------------------------
    i = 0; 
    j = 0;
    unsigned char psudo_random_byte_array[data_length];  // Store generated keystream bytes
    for (size_t k = 0; k < data_length; ++k) {
        i = (i + 1) % RC4_STATE_SIZE;
        j = (j + S[i]) % RC4_STATE_SIZE;
        swap(S, i, j);  // Swap S[i] and S[j]

        // Generate keystream byte from updated S-box
        psudo_random_byte_array[k] = S[(S[i] + S[j]) % RC4_STATE_SIZE];
    }

    // -------------------------------
    // Step 4: Encryption/Decryption
    // -------------------------------
    // XOR each byte of data with corresponding keystream byte
    // Same operation works for encryption and decryption
    for (size_t i = 0; i < data_length; ++i) {
        data[i] ^= psudo_random_byte_array[i];
    }

    return data;
}