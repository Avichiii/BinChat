#include "libraries.h"
#include "utils.h"
#include "crypto.h"
#include "client.h"
#include "main.h"
#include "globals.h"

#define MAX_USERNAME_LEN 32   // Maximum length allowed for username

// Global session object for the client.
// Stores client's name and symmetric session key (RC4 key).
client_s client_session;

/* =========================================================================================
   THREAD: Incoming Data from Server
   - Listens for incoming messages from the server.
   - Each message is received as: [4-byte length][ciphertext].
   - The ciphertext is decrypted using the session key.
   ========================================================================================= */
void *incoming_data_from_server(void *client) {
    client_data *data = ((client_data *) client);
    int client_socket = data->client_socket;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_recved;

    while (data->running) {
        // --- Step 1: Receive message length (network order) ---
        unsigned int msg_len;
        bytes_recved = recv_all(client_socket, (char *)&msg_len, sizeof(unsigned int));

        // If length not properly received, exit loop
        if (bytes_recved != sizeof(unsigned int)) {
            if (bytes_recved == 0) {
                fprintf(stderr, "INFO: Server closed the connection\n");
            } else {
                int saved_errno = errno;
                fprintf(stderr, "ERROR: Couldn't receive message length: [%s]\n", strerror(saved_errno));
            }
            
            data->running = 0;
            break;
        }

        // Convert from network byte order to host byte order
        msg_len = ntohl(msg_len);

        // Sanity check: reject oversized packets
        if (msg_len > BUFFER_SIZE) {
            fprintf(stderr, "ERROR: Message length %u exceeds BUFFER_SIZE %d\n", msg_len, BUFFER_SIZE);
            data->running = 0;
            break;
        }

        // If empty message was sent (we ignore it)
        if (msg_len == 0) {
            fprintf(stderr, "INFO: Server sent empty message\n");
            continue;
        }

        // --- Step 2: Receive the actual message payload ---
        bytes_recved = recv_all(client_socket, buffer, msg_len);
        if (bytes_recved != msg_len) {
            if (bytes_recved == 0) {
                fprintf(stderr, "INFO: Server closed the connection\n");
            } else {
                int saved_errno = errno;
                fprintf(stderr, "ERROR: Couldn't receive %u bytes from server: [%s]\n", msg_len, strerror(saved_errno));
            }
            
            data->running = 0;
            break;
        }

        // --- Step 3: Decrypt message in-place using RC4 session key ---
        rc4(client_session.s_key, buffer, msg_len); 
        buffer[msg_len - 1] = '\0';  // Ensure proper null termination

        // --- Step 4: Print message cleanly, then reprint prompt ---
        printf("\n%s\n", buffer);
        fflush(stdout);
        printf("%s# ", client_session.name);
        fflush(stdout);
    }

    return NULL;
}


/* =========================================================================================
   THREAD: Outgoing Data to Server
   - Reads input from user (stdin).
   - Encrypts it using the RC4 session key.
   - Sends the [4-byte length][ciphertext] to the server.
   ========================================================================================= */
void *outgoing_data_to_server(void *client) {
    client_data *data = ((client_data *) client);
    int client_socket = data->client_socket;
    char *buffer = (char *) malloc(BUFFER_SIZE);

    while(data->running) {
        // --- Step 1: Print the prompt ---
        char prompt[BUFFER_SIZE];
        snprintf(prompt, BUFFER_SIZE - 1, "%s# ", client_session.name);
        printf("%s", prompt);
        fflush(stdout);

        // --- Step 2: Read user input ---
        if(fgets(buffer, BUFFER_SIZE, stdin) != NULL){
            buffer[strcspn(buffer, "\n")] = '\0';  // Strip newline

            // Exit condition for client
            if(strcmp(buffer, "exit") == 0) {
                data->running = 0;
                break;
            }

            // Compute message length including null terminator
            size_t msg_len = strlen(buffer) + 1;
            if (msg_len >= BUFFER_SIZE) {
                fprintf(stderr, "ERROR: Message length %zu exceeds BUFFER_SIZE %d\n", msg_len, BUFFER_SIZE);
                data->running = 0;
                break;
            }

            // --- Step 3: Send length prefix first ---
            unsigned int net_msg_len = htonl(msg_len);
            ssize_t bytes_sent = send_all(client_socket, (char *)&net_msg_len, sizeof(unsigned int));
            if (bytes_sent != sizeof(unsigned int)) {
                int saved_errno = errno;
                fprintf(stderr, "ERROR: Couldn't send message length: %s\n", strerror(saved_errno));
                data->running = 0;
                break;
            }

            // --- Step 4: Encrypt the message ---
            char *encrypted_buffer = rc4(client_session.s_key, buffer, msg_len);
            if (!encrypted_buffer) {
                fprintf(stderr, "ERROR: Failed to encrypt message\n");
                data->running = 0;
                break;
            }

            // --- Step 5: Send encrypted payload ---
            bytes_sent = send_all(client_socket, encrypted_buffer, msg_len);
            if (bytes_sent != msg_len) {
                fprintf(stderr, "ERROR: Couldn't send %zu bytes to server: %s\n", msg_len, strerror(errno));
                data->running = 0;     
                break;
            }
        }
    }   

    free(buffer);
    return NULL;
}


/* =========================================================================================
   Function: establish_session_to_server
   - Implements handshake protocol:
        1. Send "init" packet.
        2. Receive server's public key.
        3. Generate random session key.
        4. Encrypt session key with server's RSA public key.
        5. Send encrypted session key to server.
        6. Send client's preferred username.
        7. Wait for acknowledgment ("init_ack").
   - If all succeeds, session is established.
   ========================================================================================= */
int establish_session_to_server(int client_socket, char *name) {
    // --- Step 1: Send init packet ---
    unsigned char *init_pkt = packets[0];
    unsigned short init_pkt_length = strlen(packets[0]) + 1;
    
    ssize_t bytes_send = send_all(client_socket, init_pkt, init_pkt_length);
    if (bytes_send != init_pkt_length) {
        fprintf(stderr, "ERROR: Couldn't send init_pkt to server. \n%s", strerror(errno));
        cleanup_client_resources(client_socket, NULL, NULL, NULL);
        return EXIT_FAILED;
    }
    
    // --- Step 2: Receive server's public key length ---
    unsigned int public_key_length;
    ssize_t bytes_recved = recv_all(client_socket, (unsigned char*) &public_key_length, sizeof(public_key_length));
    if(bytes_recved != sizeof(unsigned int)) {
        int saved_errno = errno;
        fprintf(stderr, "ERROR: Couldn't receive public key length [%s]\n", strerror(saved_errno));
        cleanup_client_resources(client_socket, NULL, NULL, NULL);
        return EXIT_FAILED;
    }

    // Allocate memory for key
    unsigned char *public_key = (unsigned char *) malloc(public_key_length);
    if (!public_key) {
        int saved_errno = errno;
        fprintf(stderr, "ERROR: Memory allocation for public key failed [%s]\n", strerror(saved_errno));
        cleanup_client_resources(client_socket, NULL, NULL, NULL);
        return EXIT_FAILED;
    }

    // --- Step 3: Receive actual public key ---
    bytes_recved = recv_all(client_socket, public_key, public_key_length);
    if (bytes_recved != public_key_length) {
        int saved_errno = errno;
        fprintf(stderr, "ERROR: Couldn't receive public key from server [%s]\n", strerror(saved_errno));
        cleanup_client_resources(client_socket, public_key, NULL, NULL);
        return EXIT_FAILED;
    }
    
    // --- Step 4: Generate random session key (RC4 key) ---
    unsigned char *s_key = session_key();
    if (!s_key) {
        int saved_errno = errno;
        fprintf(stderr, "ERROR: Couldn't generate session key [%s]\n", strerror(saved_errno));
        cleanup_client_resources(client_socket, public_key, NULL, NULL);
        return EXIT_FAILED;
    }
    
    // Save session info into global struct
    client_session.name = (char *) malloc(strlen(name) + 1);
    client_session.s_key = (char *) malloc(strlen(s_key) + 1);
    if(!client_session.name && !client_session.s_key) {
        int saved_errno = errno;
        fprintf(stderr, "ERROR: Couldn't allocate memory for client_session struct [%s]\n", strerror(saved_errno));
        cleanup_client_resources(client_socket, public_key, NULL, NULL);
        return EXIT_FAILED;
    }
    strcpy(client_session.name, name);
    strcpy(client_session.s_key, s_key);

    // --- Step 5: Encrypt session key with server's RSA public key ---
    enc_session_key encrypted_session_struct = encrypt(s_key, public_key);
    if (encrypted_session_struct.encrypted_s_key == NULL || encrypted_session_struct.length <= 0) {
        fprintf(stderr, "ERROR: Couldn't encrypt session key\n");
        cleanup_client_resources(client_socket, public_key, s_key, NULL);
        return EXIT_FAILED;
    }
    
    // --- Step 6: Send encrypted session key struct ---
    bytes_send = send_struct_all(client_socket, encrypted_session_struct);
    if (bytes_send == -1){
        fprintf(stderr, "ERROR: Couldn't send encrypted session key to server\n");
        cleanup_client_resources(client_socket, public_key, s_key, NULL);
        return EXIT_FAILED;
    }
    
    // --- Step 7: Send client name (length + string) ---
    int client_name_length = strlen(name) + 1;
    ssize_t client_name_length_send = send_all(client_socket, (unsigned char *) &client_name_length, sizeof(client_name_length));
    bytes_send = send_all(client_socket, name, client_name_length);
    if (bytes_send == -1 || client_name_length_send == -1){
        fprintf(stderr, "ERROR: Couldn't send client preferred name to server\n");
        cleanup_client_resources(client_socket, public_key, s_key, NULL);
        return EXIT_FAILED;
    }
   
    // --- Step 8: Wait for "init_ack" response from server ---
    unsigned short init_ack_pkt_length = strlen(packets[1]) + 1;
    unsigned char *init_ack_pkt = (unsigned char *) malloc(init_ack_pkt_length);

    bytes_recved = recv_all(client_socket, init_ack_pkt, init_ack_pkt_length);
    if (bytes_recved != init_ack_pkt_length) {
        int saved_errno = errno;
        fprintf(stderr, "ERROR: Failed to receive init_ack_pkt [%s]\n", strerror(saved_errno));
        cleanup_client_resources(client_socket, public_key, s_key, init_ack_pkt);
        return EXIT_FAILED;
    }

    init_ack_pkt[bytes_recved] = '\0';

    if(strcmp(init_ack_pkt, packets[1]) == 0) {
        cleanup_client_resources(-1, public_key, NULL, init_ack_pkt);
        return EXIT_SUCCESS;
    } else {
        cleanup_client_resources(-1, public_key, NULL, init_ack_pkt);
        return EXIT_FAILED;
    }
}


/* =========================================================================================
   Function: connection_handler
   - Orchestrates the entire lifecycle of a client connection.
   - Establishes session first.
   - Creates two threads:
        1. incoming_data_from_server
        2. outgoing_data_to_server
   - Runs until user exits or connection is lost.
   ========================================================================================= */
void connection_handler(int client_socket, char *name){
    int is_establised = establish_session_to_server(client_socket, name);
    if (is_establised == -1) {
        fprintf(stderr, "ERROR: Couldn't establish session with server.\n");
        return;
    }

    printf("--------End-to-End Encryption--------\n");

    client_data client;
    client.client_socket = client_socket;
    client.running = 1;

    pthread_t incoming_connection_thread, outgoing_connection_thread;

    // Create thread for incoming messages
    int thread_creation_status_incoming = pthread_create(&incoming_connection_thread, NULL, incoming_data_from_server, &client);
    if (thread_creation_status_incoming != 0) {
        fprintf(stderr, "ERROR: Failed to create incoming thread [%s]\n", strerror(thread_creation_status_incoming));
        close(client_socket);
        return;
    }

    // Create thread for outgoing messages
    int thread_creation_status_outgoing = pthread_create(&outgoing_connection_thread, NULL, outgoing_data_to_server, &client);
    if (thread_creation_status_outgoing != 0) {
        fprintf(stderr, "ERROR: Failed to create outgoing thread [%s]\n", strerror(thread_creation_status_outgoing));
        pthread_join(incoming_connection_thread, NULL);
        client.running = 0;
        close(client_socket);
        return;
    }

    // Detach threads (they run independently)
    pthread_detach(incoming_connection_thread);
    pthread_detach(outgoing_connection_thread);

    // Keep running until client stops
    while (client.running) {
        sleep(1);
    }

    close(client_socket);
}


/* =========================================================================================
   Helper Function: print_help
   - Prints usage instructions for the client program.
   ========================================================================================= */
void print_help(const char *prog_name) {
    fprintf(stderr, "Usage: %s <IP_ADDRESS> <PORT> <USERNAME>\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Connects to a chat server at the specified IP address and port with the given username.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  <IP_ADDRESS>  The server's IP address (e.g., 127.0.0.1)\n");
    fprintf(stderr, "  <PORT>        The server's port number (e.g., 8080)\n");
    fprintf(stderr, "  <USERNAME>    Your username (max %d characters, alphanumeric and underscores)\n", MAX_USERNAME_LEN);
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s 127.0.0.1 8080 hellsender\n", prog_name);
    exit(EXIT_FAILED);
}


/* =========================================================================================
   MAIN Function
   - Validates command-line args.
   - Creates socket and connects to server.
   - Calls connection_handler().
   ========================================================================================= */
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "ERROR: Incorrect number of arguments\n");
        print_help(argv[0]);
    }

    // --- Step 1: Create socket ---
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        fprintf(stderr, "ERROR: Client Socket Creation Failed %s\n", strerror(errno));
        return EXIT_FAILED;
    }

    // --- Step 2: Parse args ---
    char *ip = argv[1];
    int port = atoi(argv[2]);
    char *name = argv[3];

    // --- Step 3: Setup sockaddr struct ---
    struct sockaddr_in client_socket_struct;
    client_socket_struct.sin_family = AF_INET;      
    client_socket_struct.sin_port = htons(port);     
    inet_aton(ip, &client_socket_struct.sin_addr);  
    
    struct sockaddr *sock_addr; 
    sock_addr = (struct sockaddr *) &client_socket_struct;

    // --- Step 4: Connect to server ---
    int connection_status = connect(client_socket, sock_addr, sizeof(client_socket_struct));
    if (connection_status == -1) {
        fprintf(stderr, "ERROR: Couldn't connect to server %s", strerror(errno));
        close(client_socket);
        return EXIT_FAILED; 
    }
    
    // --- Step 5: Handle connection (session + chat loop) ---
    connection_handler(client_socket, name);
    
    return EXIT_SUCCESS;
}
