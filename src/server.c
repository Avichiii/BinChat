#include "crypto.h"
#include "server.h"
#include "libraries.h"
#include "utils.h"
#include "main.h"
#include "globals.h"


/**
 * Removes a client from the global client_struct_array.
 * Frees allocated memory (name, session_key), shifts array entries, 
 * and decreases client_struct_counter.
 */
void remove_client(int client_socket) {
    int index = -1;

    // Find the client in the array
    for (size_t i = 0; i < client_struct_counter; ++i) {
        if (client_struct_array[i].client_sock == client_socket) {
            index = i;
            break;
        }
    }

    // If client not found
    if (index == -1) {
        fprintf(stderr, "ERROR: Couldn't find the client\n", strerror(errno));
        return;
    }

    // Free memory for client name
    if (client_struct_array[index].client_name) {
        free(client_struct_array[index].client_name);
        client_struct_array[index].client_name = NULL;
    }

    // Free memory for client session key
    if (client_struct_array[index].session_key) {
        free(client_struct_array[index].session_key);
        client_struct_array[index].session_key = NULL;
    }

    // Shift all clients left to fill the gap
    for (int i = index; i < client_struct_counter - 1; i++) {
        client_struct_array[i] = client_struct_array[i + 1];
    }

    // Decrease active client counter
    client_struct_counter--;
}


/**
 * Broadcasts a message from one client to all others.
 * - Decrypts sender’s encrypted buffer using their session key.
 * - Formats the message with sender’s name and total client count.
 * - Encrypts the message with each receiver’s session key.
 * - Sends both message length (for framing) and encrypted data.
 */
size_t broadcast(int client_socket, char *buffer, uint32_t msg_len) {
    client sender;
    int sender_found = 0;

    // Find the sender client from socket
    for (size_t i = 0; i < client_struct_counter; ++i) {
        if (client_struct_array[i].client_sock == client_socket) {
            sender = client_struct_array[i];
            sender_found = 1;
            break;
        }
    }
    if (!sender_found) {
        fprintf(stderr, "ERROR: Sender not found for socket %d\n", client_socket);
        return EXIT_FAILED;
    }

    // Decrypt incoming encrypted message using sender's session key
    char *decrypted_buffer = rc4(sender.session_key, buffer, msg_len);
    if (!decrypted_buffer) {
        fprintf(stderr, "ERROR: Failed to decrypt incoming message for socket %d\n", client_socket);
        return EXIT_FAILED;
    }

    // Ensure decrypted message is null-terminated
    size_t message_len = strlen(decrypted_buffer);
    if (message_len >= BUFFER_SIZE) {
        fprintf(stderr, "ERROR: Decrypted message length %zu exceeds BUFFER_SIZE %d\n", message_len, BUFFER_SIZE);
        return EXIT_FAILED;
    }
    decrypted_buffer[message_len] = '\0';

    // Send message to all clients except sender
    for (size_t i = 0; i < client_struct_counter; ++i) {
        client receiver = client_struct_array[i];
        if (receiver.client_sock != sender.client_sock) {
            // Skip clients with no valid name
            if (!receiver.client_name || strlen(receiver.client_name) == 0) {
                fprintf(stderr, "ERROR: Invalid or empty client_name for socket %d\n", receiver.client_sock);
                continue;
            }

            // Format message with sender name and total clients
            char new_buffer[BUFFER_SIZE];
            int formatted_len = snprintf(
                new_buffer, BUFFER_SIZE, "%s (c: %zu)# %s", 
                sender.client_name, client_struct_counter, decrypted_buffer
            );
            if (formatted_len < 0 || formatted_len >= BUFFER_SIZE) {
                fprintf(stderr, "ERROR: Message formatting failed or too long for socket %d\n", receiver.client_sock);
                continue;
            }

            // Encrypt formatted message with receiver’s session key
            char *encrypted_buffer = rc4(receiver.session_key, new_buffer, formatted_len + 1);
            if (!encrypted_buffer) {
                fprintf(stderr, "ERROR: Failed to encrypt message for socket %d\n", receiver.client_sock);
                continue;
            }
            
            // Send message length first (network byte order for consistency)
            unsigned int net_len = htonl(formatted_len + 1);
            ssize_t bytes_sent = send_all(receiver.client_sock, (char *)&net_len, sizeof(unsigned int));
            if (bytes_sent != sizeof(unsigned int)) {
                fprintf(stderr, "ERROR: Failed to send message length to client %d: [%s]\n",
                        receiver.client_sock, strerror(errno));
                continue;
            }

            // Send actual encrypted message
            bytes_sent = send_all(receiver.client_sock, encrypted_buffer, formatted_len + 1);
            if (bytes_sent != formatted_len + 1) {
                fprintf(stderr, "ERROR: Failed to broadcast to client %d: [%s]\n",
                        receiver.client_sock, strerror(errno));
                continue;
            }
        }
    }

    return EXIT_SUCCESS;
}


/**
 * Performs the handshake to establish a secure client session:
 * 1. Receives init packet and compares with expected value.
 * 2. Sends server’s RSA public key to client.
 * 3. Receives client’s encrypted session key.
 * 4. Receives client’s chosen display name.
 * 5. Decrypts session key using server’s private key.
 * 6. Adds client info (socket, session key, name) to global array.
 * 7. Sends init Acknowledgement packet to client
 */
int establish_client_session(int client_socket) {
    // Step 1: Receive and verify init packet
    unsigned char *init_pkt = packets[0];
    unsigned short init_pkt_len = strlen(packets[0]) + 1; 
    unsigned char *client_sent_init_pkt = (unsigned char *) malloc(init_pkt_len);

    if (!client_sent_init_pkt) {
        fprintf(stderr, "ERROR: Unable to allocate memory for client init pkt [%s]\n", strerror(errno));
        close(client_socket);
        return EXIT_FAILED;
    }

    ssize_t bytes_recved = recv_all(client_socket, client_sent_init_pkt, init_pkt_len);
    if (bytes_recved != init_pkt_len || bytes_recved <= 0){
        fprintf(stderr, "ERROR: Unable to receive init pkt\n");
        cleanup_server_resources(client_socket, NULL, client_sent_init_pkt, NULL, NULL);
        return EXIT_FAILED;
    }
    
    if (strcmp(client_sent_init_pkt, init_pkt) == 0) {
        // Step 2: Send server’s RSA public key
        FILE *public_key_fptr = fopen(PATH_TO_PUBLIC_KEY, "r");
        if (!public_key_fptr){
            fprintf(stderr, "ERROR: Could not load Public key file [%s]\n", strerror(errno));
            cleanup_server_resources(client_socket, NULL, client_sent_init_pkt, NULL, NULL);
            return EXIT_FAILED;
        }

        // Determine public key file length
        fseek(public_key_fptr, 0, SEEK_END);
        unsigned int public_key_length = ftell(public_key_fptr);
        rewind(public_key_fptr);

        // Read public key into memory
        unsigned char *public_key = (unsigned char *) malloc(public_key_length);
        if (!public_key){
            fprintf(stderr, "ERROR: Unable to allocate memory for public_key [%s]\n", strerror(errno));
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, NULL, NULL);
            return EXIT_FAILED;
        }

        size_t bytes_read = fread(public_key, 1, public_key_length, public_key_fptr);
        if (bytes_read != public_key_length) {
            fprintf(stderr, "ERROR: Unable to read full public key file\n");
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, public_key, NULL);
            return EXIT_FAILED;
        }

        // Send public key length first
        ssize_t bytes_sent = send_all(client_socket, (unsigned char*) &public_key_length, sizeof(public_key_length));
        if (bytes_sent != sizeof(unsigned int)) {
            fprintf(stderr, "ERROR: Couldn't send public key length\n");
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, public_key, NULL);
            return EXIT_FAILED;
        }

        // Send actual public key
        bytes_sent = send_all(client_socket, public_key, public_key_length);
        if (bytes_sent != public_key_length || bytes_sent <= 0) {
            fprintf(stderr, "ERROR: Unable to send full public key\n");
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, public_key, NULL);
            return EXIT_FAILED;
        }

        // Step 3: Receive encrypted session key from client
        enc_session_key encrypted_session_struct = recv_struct_all(client_socket, encrypted_session_struct);
        if (encrypted_session_struct.length <= 0 || encrypted_session_struct.encrypted_s_key == NULL) {
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, public_key, NULL);
            return EXIT_FAILED;
        }

        // Step 4: Receive client name
        int client_name_length = 0;
        recv_all(client_socket, (unsigned char *) &client_name_length, sizeof(int));
        char *name = (char *) malloc(client_name_length);
        bytes_recved = recv_all(client_socket, name, client_name_length);
        if (bytes_recved == -1 || client_name_length <= 0){
            fprintf(stderr, "ERROR: Couldn't receive client name [%s]\n", strerror(errno));
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, public_key, NULL);
            return EXIT_FAILED;
        }

        // Step 5: Decrypt session key using server’s private RSA key
        unsigned char *s_key = decrypt(encrypted_session_struct);
        if (!s_key) {
            fprintf(stderr, "ERROR: Unable to Decrypt RSA Encrypted Session Key [%s]\n", strerror(errno));
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, public_key, NULL);
            return EXIT_FAILED;
        }
        
        free(encrypted_session_struct.encrypted_s_key);

        // Step 6: Send ACK back to client
        unsigned char *init_ack_pkt = packets[1];
        unsigned short init_ack_pkt_len = strlen(packets[1]) + 1; 
        bytes_sent = send_all(client_socket, init_ack_pkt, init_ack_pkt_len);
        if (bytes_sent != init_ack_pkt_len || bytes_sent <= 0) {
            fprintf(stderr, "ERROR: Unable to send init ACK\n");
            cleanup_server_resources(client_socket, public_key_fptr, client_sent_init_pkt, public_key, s_key);
            return EXIT_FAILED;
        }

        // Save client details into global array
        client new_client;
        new_client.client_sock = client_socket;
        new_client.session_key = s_key;
        new_client.client_name = name;

        client_struct_array[client_struct_counter] = new_client;
        client_struct_counter++;

        return EXIT_SUCCESS;
    }

    fprintf(stderr, "ERROR: Init Packet mismatch\n");
    cleanup_server_resources(client_socket, NULL, client_sent_init_pkt, NULL, NULL);
    return EXIT_FAILED;
}


/**
 * Handles communication with a single connected client.
 * 1. Establishes session via handshake (RSA exchange, session key setup).
 * 2. Loops: receives message length + encrypted message.
 * 3. Forwards (via broadcast) to all other clients.
 * 4. Handles disconnects and errors cleanly.
 */
void *connections(void *client_sock) {
    int client_socket = *((int *)client_sock);
    int is_established = establish_client_session(client_socket);
    if (is_established == -1) {
        fprintf(stderr, "ERROR: Client Session couldn't be initiated\n");
        return NULL;
    }
    
    // Free temporary socket memory
    free(client_sock);

    int run = 1;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_recved;

    // Main loop for client communication
    while (run) {
        unsigned int msg_len;

        // Step 1: Receive message length
        bytes_recved = recv_all(client_socket, (char *)&msg_len, sizeof(unsigned int));
        if (bytes_recved != sizeof(unsigned int)) {
            fprintf(stderr, "ERROR: Couldn't receive message length: [%s]\n", strerror(errno));
            remove_client(client_socket);
            run = 0;
            continue;  
        }

        msg_len = ntohl(msg_len); // Convert length back to host byte order

        // Step 2: Receive actual encrypted message
        bytes_recved = recv_all(client_socket, buffer, msg_len);
        
        if (bytes_recved == msg_len) {
            // Step 3: Broadcast message to all other clients
            size_t broadcast_status = broadcast(client_socket, buffer, msg_len);
            if (broadcast_status == EXIT_FAILED) {
                fprintf(stderr, "ERROR: Broadcast Failed");
            }

        } else if (bytes_recved == 0) {
            fprintf(stderr, "INFO: Client disconnected! [%s]\n", strerror(errno));
            remove_client(client_socket);
            run = 0;

        } else {
            fprintf(stderr, "ERROR: Closing Client Connection due to error. [%s]\n", strerror(errno));
            remove_client(client_socket);
            run = 0;
        }
    }

    // Cleanup client socket
    close(client_socket);
    return NULL;
}


/**
 * Starts the main server loop:
 * - Accepts new client connections.
 * - Spawns a thread for each client (connections handler).
 * - Limits max clients (CONNECTION_LIMIT).
 */
int server_start(int server_socket) {
    fputs("Server is Listening for connections...\n", stdout);
    fflush(stdout);

    pthread_t threads[CONNECTION_LIMIT];
    size_t i = 0;

    while (true) {
        // Prevent new connections when limit is reached
        if (connection_counter >= CONNECTION_LIMIT){
            fprintf(stderr, "Error: Maximum Client Limit reached %d\n", CONNECTION_LIMIT);

            // Accept and immediately reject new connection with message
            int temp_c_socket = accept(server_socket, NULL, NULL);
            if (temp_c_socket != -1) {
                unsigned char *response = "Server is currently busy, try again later";
                send(temp_c_socket, response, strlen(response), 0);
                close(temp_c_socket);
            }
            sleep(1);
            continue;
        }
        
        // Accept new client connection
        int client_socket = accept(server_socket, NULL, NULL);

        // Allocate memory to safely pass socket to new thread
        int *client_s_ptr = (int *) malloc(sizeof(int));
        if(!client_s_ptr) continue;
        *client_s_ptr = client_socket;

        if (client_socket == -1) {
            fprintf(stderr, "ERROR: Failed to accept new client [%s]\n", strerror(errno));
            free(client_s_ptr);
            continue;
        }

        // Spawn a thread for the client
        int thread_creation_status = pthread_create(&threads[i], NULL, connections, client_s_ptr);
        if (thread_creation_status == 0) {
            pthread_detach(threads[i]); // Detach so we don’t need to join later
        } else {
            fprintf(stderr, "ERROR: Unable to Create a New Thread %d\n", thread_creation_status);
            close(client_socket);
            free(client_s_ptr);
            continue;
        }

        i++;
        connection_counter++;
    }

    return EXIT_SUCCESS;
}


/**
 * Prints usage instructions for running the server.
 */
void print_help(const char *prog_name) {
    fprintf(stderr, "Usage: %s <IP_ADDRESS> <PORT>\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Connects to a chat server at the specified IP address and port.\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  <IP_ADDRESS>  The server's IP address (e.g., 127.0.0.1)\n");
    fprintf(stderr, "  <PORT>        The server's port number (e.g., 8080)\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s 127.0.0.1 8080\n", prog_name);
    exit(EXIT_FAILED);
}


/**
 * Entry point:
 * 1. Validates arguments (IP + Port).
 * 2. Creates and binds server socket.
 * 3. Starts listening for clients.
 * 4. Runs server loop (server_start).
 */
int main(int argc, char *argv[]) {
    if(argc != 3) {
        fprintf(stderr, "ERROR: Incorrect number of arguments\n");
        print_help(argv[0]);
    }

    // Step 1: Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        fprintf(stderr, "ERROR: Couldn't Create Server Socket %s\n", strerror(errno));
        return EXIT_FAILED;
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);

    // Step 2: Setup socket struct (IP + port)
    struct sockaddr_in server_socket_struct;
    server_socket_struct.sin_family = AF_INET;
    server_socket_struct.sin_port = htons(port);
    inet_aton(ip, &server_socket_struct.sin_addr);

    struct sockaddr *server_s_struct = (struct sockaddr *) &server_socket_struct; 

    // Allow reusing socket quickly after restart
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Step 3: Bind and listen
    bind(server_socket, server_s_struct, sizeof(server_socket_struct));
    listen(server_socket, CONNECTION_LIMIT);

    // Step 4: Start server main loop
    server_start(server_socket);

    return 0;
}