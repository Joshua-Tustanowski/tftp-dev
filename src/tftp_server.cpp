#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/_endian.h>
#include "include/struct.h"

#define PORT "8080"
#define MAXBUFLEN 100
#define DEBUG false
#define MAX_BLOCK_SIZE 512


void print_tftp_rqq(struct tftp_rqq *request) {
    printf("opcode - %d\n", request->opcode);
    printf("file_name - %s\n", request->file_name);
    printf("mode - %s\n", request->mode);
}

int handle_ack_from_client(int sockfd, struct sockaddr *p, socklen_t *addr_len, int expected_block_id){
    char buffer[32];
    int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, p, addr_len);
    if (bytes_received < 4) {
        fprintf(stderr, "Invalid packet received\n");
        return -1;
    }
    // Parse ACK packet
    uint16_t opcode = ntohs(*(uint16_t*)buffer);
    uint16_t block_id = ntohs(*(uint16_t*)(buffer + 2));
    
    if (opcode != 4) {  // Not an ACK packet
        fprintf(stderr, "Expected ACK packet, got opcode %d\n", opcode);
        return -1;
    }

    if (block_id != expected_block_id) {
        fprintf(stderr, "Expected block %d, got %d\n", expected_block_id, block_id);
        return -1;
    }
    printf("Got ACK for block: %d\n", block_id);
    return 0;
}

struct tftp_error create_error_message(uint16_t error_code, const char * error_message){
    struct tftp_error message{.opcode=(uint16_t)5, .error_code=error_code};
    memset(message.error_message, 0, 512);
    memcpy(message.error_message, error_message, strlen(error_message) + 1);
    return message;
}

int create_tftp_buffer_for_error_packet(struct tftp_error *packet ,char *buffer) {
    int offset = 0;
    
    // Pack opcode (2 bytes, network byte order)
    uint16_t opcode = htons(packet->opcode);  // RRQ
    memcpy(buffer + offset, &opcode, 2);
    offset += 2;
    
    // Pack BlockId
    uint16_t block_id = htons(packet->error_code);
    memcpy(buffer + offset, &block_id, 2);
    offset += 2;
    
    // Pack Error Message Itself
    strcpy(buffer + offset, packet->error_message);
    offset += strlen(packet->error_message) + 1;
    return offset;
}


int send_error_message(
    uint16_t error_code, 
    const char * error_message,
    int socketfd,
    struct sockaddr* p
) {
    struct tftp_error packet = create_error_message(error_code, error_message);
    char buffer[1024];
    memset(buffer, 0, 1024);
    int packet_length = create_tftp_buffer_for_error_packet(&packet, buffer);
    fprintf(stdout, "Sending num_bytes: %d to socket info\n", packet_length);
    int num_bytes = sendto(
        socketfd, 
        buffer,
        packet_length,
        0,
        p, 
        p->sa_len
    );
    if (num_bytes == -1) {
        perror("oh no - failed to send error message to client.\n");
        exit(1);
    }
    return 0;
}

struct tftp_rqq deserialise_request(uint16_t op_code, char *buffer, int length) {
    struct tftp_rqq request;
    request.opcode = op_code;
    int offset = 2;

    // parsing out the file_name
    int fn_idx = 0;
    for (int i = offset; i < length; i++){
        if (buffer[i] == 0) {
            break;
        }
        request.file_name[fn_idx] = buffer[i];
        fn_idx++;
        offset++;
    }
    request.file_name[fn_idx + 1] = '\0';


    int mode_idx = 0;
    for (int j = offset + 1; j < length; j++){
        if (buffer[j] == 0) {
            break;
        }
        request.mode[mode_idx] = buffer[j];
        mode_idx++;
        offset++;
    }

    request.mode[mode_idx + 1] = '\0';
    return request;
}

void * get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    fprintf(stderr, "IPv6 is not supported\n");
    exit(2);
}

int file_exists(const char *file_name) {
    FILE *fp;
    fp = fopen(file_name, "r");
    if (fp == NULL) {
        return 0;
    }
    fclose(fp);
    return 1;
}

struct tftp_data* create_data(struct tftp_rqq* request, int *num_packets) {
    fprintf(stdout, "Trying to send data for '%s'\n", request->file_name);

    char *file_buffer = NULL;
    long file_size = 0;

    if (file_exists(request->file_name) == 1) {
        fprintf(stdout, "File-Name found on the system %s\n", request->file_name);
        // file_buffer = "Hello This is Example Data";
        FILE *fp = fopen(request->file_name, "rb");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: Could not open file %s\n", request->file_name);
            *num_packets = 0;
            return NULL;
        }

        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        // Allocate buffer for entire file
        file_buffer = (char*)malloc(file_size + 1);
        if (file_buffer == NULL) {
            fprintf(stderr, "Error: Could not allocate memory for file\n");
            fclose(fp);
            *num_packets = 0;
            return NULL;
        }

        // Read entire file into buffer
        size_t bytes_read = fread(file_buffer, 1, file_size, fp);
        if (bytes_read != file_size) {
            fprintf(stderr, "Error: Could not read entire file\n");
            free(file_buffer);
            fclose(fp);
            *num_packets = 0;
            return NULL;
        }

        file_buffer[file_size] = '\0';  // Null terminate for safety
        fclose(fp);

        fprintf(stdout, "Successfully read %ld bytes from %s\n", file_size, request->file_name);
    }
    else {
        fprintf(stderr, "File not found: %s\n", request->file_name);
        *num_packets = 0;
        return NULL;  // Return NULL to indicate file not found
    }
    int num_blocks = (file_size + MAX_BLOCK_SIZE - 1) / MAX_BLOCK_SIZE;
    if (num_blocks == 0) {
        num_blocks = 1;
    }

    struct tftp_data* blocks = (struct tftp_data*)malloc(num_blocks * sizeof(struct tftp_data));
    if (blocks == NULL) {
        fprintf(stderr, "Error: Could not allocate memory for blocks\n");
        free(file_buffer);
        *num_packets = 0;
        return NULL;
    }

    for (int i=0; i<num_blocks; i++) {
        blocks[i].opcode = 3;
        blocks[i].block_id = i + 1; // TFTP blocks start at 1
        memset(blocks[i].data, 0, MAX_BLOCK_SIZE);
        
        // Copy data for this block
        int bytes_to_copy = (i == num_blocks - 1) ?  file_size - (i * MAX_BLOCK_SIZE) : MAX_BLOCK_SIZE;
        memcpy(blocks[i].data, file_buffer + (i * MAX_BLOCK_SIZE), bytes_to_copy);
        blocks[i].data_size = (uint16_t)bytes_to_copy;
    }
    free(file_buffer);
    *num_packets = num_blocks;
    return blocks;
}

void free_data(struct tftp_data* blocks) {
    free(blocks);
}

int create_tftp_buffer_for_data_packet(struct tftp_data *packet ,char *buffer) {
    int offset = 0;
    
    // Pack opcode (2 bytes, network byte order)
    uint16_t opcode = htons(packet->opcode);  // RRQ
    memcpy(buffer + offset, &opcode, 2);
    offset += 2;
    
    // Pack BlockId
    uint16_t block_id = htons(packet->block_id);
    memcpy(buffer + offset, &block_id, 2);
    offset += 2;
    
    // Pack Data Buffer
    memcpy(buffer + offset, packet->data, packet->data_size);
    offset += packet->data_size;    
    return offset;
}

void handle_read_request(
    struct tftp_rqq* request,
    int socketfd,
    struct sockaddr* p
) {
    // 1. parse out the buffer.
    // 2. create a Data packet
    // 3. send this back to the client who requested it. (for all the blocks)
    int count = 0;
    struct tftp_data* packets = create_data(request, &count);
    if (packets == NULL || count == 0) {
        send_error_message((uint16_t)1, "File not found", socketfd, p);
        return;
    }
    for (int i = 0; i < count; i++) {
        // serialise the struct into bytes to send to the client.
        struct tftp_data packet = packets[i];
        char buffer[1024];
        memset(buffer, 0, 1024);
        int packet_length = create_tftp_buffer_for_data_packet(&packet, buffer);
        fprintf(stdout, "Sending num_bytes: %d to socket info\n", packet_length);
        int num_bytes = sendto(
            socketfd, 
            buffer,
            packet_length,
            0,
            p, 
            p->sa_len
        );
        if (num_bytes == -1) {
            perror("oh no - failed to send DATA packet to client\n");
            exit(1);
        }

        // Now we need to wait to get an ACK pack from the client.
        socklen_t addr_len = sizeof(struct sockaddr_storage);
        int result = handle_ack_from_client(socketfd, p, &addr_len, packet.block_id);

    }
    free_data(packets);
}


int main() {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;

    int rv;
    int num_bytes;
    struct sockaddr_storage their_addr;
    socklen_t addr_len;

    char buf[MAXBUFLEN];
    char s[INET_ADDRSTRLEN];


    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    // fprintf(stdout, "Hints Structure - %d\n", hints.ai_socktype);
    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure
    
    while (1) {
        printf("listener: waiting to recvfrom...\n");

        addr_len = sizeof(their_addr);
        if ((num_bytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        printf("listener: got packet from %s\n",
            inet_ntop(
                their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                s, 
                sizeof(s)
            )
        );

        if (num_bytes < 2) {
            perror("received too few bytes");
            exit(1);
        }

        uint16_t op_code = ntohs(*(uint16_t*)buf);
        switch (op_code) {
            case 1: {
                struct tftp_rqq request = deserialise_request(op_code, buf, num_bytes); 
                handle_read_request(&request, sockfd, (struct sockaddr *)&their_addr);
                break;
            }
            case 2: {
                printf("Got a write request\n");
                send_error_message((uint16_t)0, "Writes not supported", sockfd, (struct sockaddr *)&their_addr);
                break;
            }
            case 4: {
                printf("Got ACK packet\n");
                break;
            }
            default:
                fprintf(stderr, "op-code %d not supported currently\n", op_code);
                char error_msg[256];
                snprintf(
                    error_msg, 
                    sizeof(error_msg), 
                    "Op-Code not supported %d", 
                    op_code
                );
                // How can i have a formatted string here to include the op-code?
                send_error_message((uint16_t)0, error_msg, sockfd, (struct sockaddr *)&their_addr);
                break;
        }
    }
    close(sockfd);
    return 0;
}