/*
** tftp_client.c -- a datagram "client"
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "include/struct.h"

#define SERVERPORT "8080"


int get_tftp_rqq_length(struct tftp_rqq* request) {
    return sizeof(uint16_t) + strlen(request->file_name) + strlen(request->mode);
}

struct tftp_rqq create_read_request(char *file_name) {
   struct tftp_rqq request;
   request.opcode = 1;
   strcpy(request.file_name, file_name);
   strcpy(request.mode, "netascii");
   return request;
}

int create_tftp_request_buffer(struct tftp_rqq* request, char *buffer) {
    int offset = 0;
    
    // Pack opcode (2 bytes, network byte order)
    uint16_t opcode = htons(request->opcode);  // RRQ
    memcpy(buffer + offset, &opcode, 2);
    offset += 2;
    
    // Pack filename + null terminator
    strcpy(buffer + offset, request->file_name);
    offset += strlen(request->file_name) + 1;
    
    // Pack mode + null terminator
    strcpy(buffer + offset, request->mode);
    offset += strlen(request->mode) + 1;
    
    return offset;
}


int send_read_request(struct addrinfo* p, char* file_name, int sockfd) {
    // Create the Read Request Buffer.
    /*
    2 bytes     string    1 byte     string   1 byte
    ------------------------------------------------
    | Opcode |  Filename  |   0  |    Mode    |   0  |
    ------------------------------------------------
    */
   struct tftp_rqq read_request = create_read_request(file_name);
   char buffer[512];
   memset(buffer, 0, 512);
   int packet_length = create_tftp_request_buffer(&read_request, buffer);
   int num_bytes = sendto(
        sockfd, 
        buffer,
        packet_length,
        0,
        p->ai_addr, 
        p->ai_addrlen
    );
    if (num_bytes == -1) {
        perror("oh no\n");
        exit(1);
    }

    return num_bytes;
}

int receive_file(int sockfd, struct sockaddr *server_addr, socklen_t addr_len) {
    char buffer[MAX_BLOCK_SIZE + 4]; // include 4 bytes of the header + data
    uint16_t expected_block_id = 1;
    while (true) {
       // Receive DATA packet
        int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, server_addr, &addr_len);
        if (bytes_received < 4) {
            fprintf(stderr, "Invalid packet received\n");
            return -1;
        }
        // Parse DATA packet
        uint16_t opcode = ntohs(*(uint16_t*)buffer);
        uint16_t block_id = ntohs(*(uint16_t*)(buffer + 2));
        
        if (opcode != 3) {  // Not a DATA packet
            fprintf(stderr, "Expected DATA packet, got opcode %d\n", opcode);
            return -1;
        }

        if (block_id != expected_block_id) {
            fprintf(stderr, "Expected block %d, got %d\n", expected_block_id, block_id);
            return -1;
        }
        
        // Process the data
        int data_length = bytes_received - 4;
        printf("Received block %d with %d bytes\n", block_id, data_length);
        
        // Write data to stdout or file
        fwrite(buffer + 4, 1, data_length, stdout);
        // Send ACK
        struct tftp_ack ack = {htons(4), htons(block_id)};
        sendto(sockfd, &ack, sizeof(ack), 0, server_addr, addr_len);
        
        // Check if this is the last block (less than 512 bytes)
        if (data_length < 512) {
            printf("\nFile transfer complete\n");
            break;
        }
        expected_block_id++;
    }
    return 0;
}


int main(int argc, char *argv[])
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    if (argc != 3) {
        fprintf(stderr,"usage: talker hostname message\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;

    rv = getaddrinfo(argv[1], SERVERPORT, &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        return 2;
    }

    int bytes_sent = send_read_request(p, argv[2], sockfd);
    printf("TFTP Client: Sent %d bytes to %s\n", bytes_sent, argv[1]);
    receive_file(sockfd, p->ai_addr, p->ai_addrlen);

    freeaddrinfo(servinfo);


    close(sockfd);

    return 0;
}