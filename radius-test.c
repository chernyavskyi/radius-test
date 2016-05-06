#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#include <errno.h>

#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/md5.h>

#define LOG_E(...) fprintf(stderr, ## __VA_ARGS__)

typedef struct __attribute__((__packed__)) status_request_packet {
    unsigned char code;
    unsigned char identifier;
    unsigned char size[2];
    unsigned char authentificator[16];
    struct __attribute__((__packed__)) {
        unsigned char type;
        unsigned char length;
        unsigned char string[16];
    } attribute;
} status_request_packet_t;

typedef struct __attribute__((__packed__)) status_response_packet {
    unsigned char code;
    unsigned char identifier;
    unsigned char size[2];
    unsigned char authentificator[MD5_DIGEST_SIZE];
} status_response_packet_t;

#define STATUS_SERVER_RADIUS_CODE 0x0c
#define STATUS_SERVER_RADIUS_IDENTIFIER 0x0a
#define ACCESS_ACCEPT_RADIUS_CODE 0x02

#define RADIUS_KEY_MAX_SIZE 64

#define DEFAULT_TIMEOUT 2

static int status_request_packet_make(status_request_packet_t *packet,
                                      const char *key,
                                      size_t ksize) {
    Hmac hmac;
	packet->code = STATUS_SERVER_RADIUS_CODE;
    packet->identifier = STATUS_SERVER_RADIUS_IDENTIFIER;
    packet->size[0] = 0x0;
    packet->size[1] = sizeof(*packet);

    packet->attribute.type = 0x50;
    packet->attribute.length = 18;
    memset(packet->attribute.string, 0, 16);

    HmacSetKey(&hmac, MD5, *((unsigned char **) &key), ksize);
    HmacUpdate(&hmac, (unsigned char *) packet, sizeof(*packet));
    HmacFinal(&hmac, packet->attribute.string);

    return 0;
}

static int status_packet_check_response(const status_response_packet_t *resp_packet,
                                        const unsigned char *authentificator,
                                        const char *key,
                                        size_t ksize) {
    status_response_packet_t md5_packet;
    unsigned char comp_authentificator[MD5_DIGEST_SIZE];
    Md5 md5;

    memcpy(&md5_packet, resp_packet, sizeof(*resp_packet) - sizeof(resp_packet->authentificator));
    memcpy(md5_packet.authentificator, authentificator, MD5_DIGEST_SIZE);

    InitMd5(&md5);
    Md5Update(&md5, (unsigned char *) &md5_packet, sizeof(md5_packet));
    Md5Update(&md5, (unsigned char *)key, ksize);

    Md5Final(&md5, comp_authentificator);

    if (resp_packet->code != ACCESS_ACCEPT_RADIUS_CODE)
        return -1;
    else if (resp_packet->size[0] != 0x0 || resp_packet->size[1] != 0x14)
        return -1;
    else if (memcmp(resp_packet->authentificator, comp_authentificator, MD5_DIGEST_SIZE))
        return -1;
    else
        return 0;
}

static int send_status_packet(int sockfd, const char *key_str) {
    size_t ksize;
    ssize_t nbytes;
    status_request_packet_t request_packet;

    ksize = strlen(key_str);
    memset(&request_packet, 0, sizeof(request_packet));
    status_request_packet_make(&request_packet, key_str, ksize);

    nbytes = send(sockfd, (void *)&request_packet, sizeof(request_packet), 0);
    if (nbytes == -1) {
        LOG_E("send err=%s", strerror(errno));
        return -1;
    }

    status_response_packet_t response_packet;
    memset(&response_packet, 0, sizeof(response_packet));
    nbytes = recv(sockfd, (void *)&response_packet, sizeof(response_packet), 0);
    if (nbytes == -1) {
        perror("recv");
        return -1;
    }

    return status_packet_check_response(&response_packet, request_packet.authentificator, key_str, ksize);
}

static int connect_to_server(const char *addr, const char *port, int timeout_sec) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sockfd, err;
    struct timeval timeout = {timeout_sec, 0};

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    err = getaddrinfo(addr, port, &hints, &result);
    if (err != 0) {
        LOG_E("getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype,
                     rp->ai_protocol);
        if (sockfd < 0)
            continue;

        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

        err = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (err < 0) {
            close(sockfd);
            continue;
        } else {
            freeaddrinfo(result);
            return sockfd;
        }
    }

    LOG_E("Could not create socket\n");
    freeaddrinfo(result);

    return -1;
}

static void usage(const char *name, int exitcode) {
    FILE *out;

    if (exitcode == EXIT_SUCCESS) {
        out = stdout;
    } else {
        out = stderr;
    }

    fprintf(out, "Usage: %s ADDR PORT SECRET [TIMEOUT]\n", name);
    fprintf(out, "Send the Status-Request packet to a RADIUS server at the ADDR:PORT endpoint\n");
    fprintf(out, "using the shared secret SECRET and wait [TIMEOUT] seconds until the response\n");
    fprintf(out, "received. Default timeout is 2 seconds\n");
    fprintf(out, "\n\t-h\tDisplay this help and exit\n");
    exit(exitcode);
}

int main(int argc, char **argv) {
    int timeout, sockfd;

    if (argc == 2 && !strcmp(argv[1], "-h")) {
        usage(argv[0], EXIT_SUCCESS);
    } else if (argc != 4 && argc != 5) {
        usage(argv[0], EXIT_FAILURE);
    }

    if (argc == 5) {
        timeout = atoi(argv[4]);
    } else {
        timeout = DEFAULT_TIMEOUT;
    }

    sockfd = connect_to_server(argv[1], argv[2], timeout);
    if (sockfd < 0) {
        LOG_E("Couldn't create  socket\n");
        return EXIT_FAILURE;
    }

    if (send_status_packet(sockfd, argv[3]) < 0) {
        LOG_E("Status error\n");
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}
