#include <stdlib.h>
#define MAX_BLOCK_SIZE 512

struct tftp_rqq {
    uint16_t opcode; // Should be 1 for read
    char file_name[256];
    char mode[10];
};

struct tftp_write {
    uint16_t opcode; // Should be 2 for write
    char file_name[256];
    char mode[10];
};

struct tftp_data {
    /*
    Packet Structure.
         2 bytes    2 bytes       n bytes
          ---------------------------------
   DATA  | 03    |   Block #  |    Data    |
          ---------------------------------
    */
    uint16_t opcode;  // Should be 3 for DATA
    uint16_t block_id;
    uint8_t data[MAX_BLOCK_SIZE];
    uint16_t data_size;
};

struct tftp_ack {
    uint16_t opcode;    // Should be 4 for ACK
    uint16_t block_id;
};

struct tftp_error {
    /*
    ErrorCode Values -> ...
    Value     Meaning
    0         Not defined, see error message (if any).
    1         File not found.
    2         Access violation.
    3         Disk full or allocation exceeded.
    4         Illegal TFTP operation.
    5         Unknown transfer ID.
    6         File already exists.
    7         No such user.
    */
    uint16_t opcode;    // Should be 5 for ERROR
    uint16_t error_code;
    char error_message[512];
};