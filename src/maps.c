#include <xdp/libxdp.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include "maps.h"
#include "loader.h"

void get_maps(struct xdp_program *prog, xdp_maps_t *xdp_maps)
{
    // Get bpf object
    struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);

    // Get maps
    xdp_maps->xsks_map = bpf_object__find_map_fd_by_name(bpf_obj, "xsks_map");
    xdp_maps->a2s_players = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_players");
    xdp_maps->a2s_info = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_info");
    xdp_maps->hash_key = bpf_object__find_map_fd_by_name(bpf_obj, "hash_key");
    xdp_maps->timestamp = bpf_object__find_map_fd_by_name(bpf_obj, "timestamp_map");
}

int a2s_query(char *ip, int port, xdp_maps_t *dst, __u8 header)
{
    printf("Gathering for %s:%d\n", ip, port);
    // Create socket to be used to send the requests to the game server
    int sockfd;
    struct sockaddr_in servaddr;
    char buffer[MAX_A2S_SIZE];
    
    // Define our variables for interacting with the xdp maps
    struct server_key xdp_key = {0};
    struct a2s_val val = {0};
    __u32 index = 0;
    socklen_t len;

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        perror("Socket creation failed");
        return -1;
    }

    // Set socket timeout
    struct timespec timeout;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt failed\n");
        return -1;
    }

    // Fill server information
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(ip);

    // Send A2S_INFO or A2S_PLAYER request based on header
    if (header == 0x54)
    {
        sendto(sockfd, "\xFF\xFF\xFF\xFF\x54Source Engine Query\x00", 25, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
    }
    else if (header == 0x55)
    {
        sendto(sockfd, "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF", 9, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
    }

    // Receive and store response
    len = sizeof(servaddr);
    int n = recvfrom(sockfd, (char *)buffer, MAX_A2S_SIZE, MSG_WAITALL, (struct sockaddr *)&servaddr, &len);
    if (n < 0)
    {
        printf("Timeout occurred\n");
        close(sockfd);
        return -1;
    }
    buffer[n] = '\0';

    // Check if the server sent a challenge number
    if (buffer[4] == 0x41)
    {
        // Extract the challenge number from the response
        int challenge_number = *(int *)(buffer + 5);

        // Prepare the challenge response
        char challenge_response[29] = "\xFF\xFF\xFF\xFF\x54Source Engine Query\x00";
        char challenge_response_players[13] = "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF";

        if (header == 0x54)
        {
            memcpy(challenge_response + 25, &challenge_number, 4);
            // Send challenge response
            sendto(sockfd, challenge_response, 29, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
        }
        else if (header == 0x55)
        {
            memcpy(challenge_response_players + 5, &challenge_number, 4);
            // Send challenge response
            sendto(sockfd, challenge_response_players, 13, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
        }

        // Receive and store response
        n = recvfrom(sockfd, (char *)buffer, MAX_A2S_SIZE, MSG_WAITALL, (struct sockaddr *)&servaddr, &len);
        if (n < 0)
        {
            printf("Timeout occurred\n");
            close(sockfd);
            return -1;
        }
        buffer[n] = '\0';
    }

    close(sockfd);

    // Fill xdp_key and val
    xdp_key.ip = servaddr.sin_addr.s_addr;
    xdp_key.port = servaddr.sin_port;
    val.size = n;

    if (bpf_map_lookup_elem(dst->timestamp, &index, &val.expires) != 0)
    {
        perror("Failed to get timestamp");
        return -1;
    }

    val.expires += 10000000000UL;
    memcpy(val.data, buffer, n);

    // Update xdp map
    if (header == 0x54)
    {
        if (bpf_map_update_elem(dst->a2s_info, &xdp_key, &val, BPF_ANY) < 0)
        {
            perror("Failed to update value");
            return -1;
        }
    }
    else if (header == 0x55)
    {
        if (bpf_map_update_elem(dst->a2s_players, &xdp_key, &val, BPF_ANY) < 0)
        {
            perror("Failed to update value");
            return -1;
        }
    }
    return 0;
}

void gather_from_servers(void *args)
{
    xdp_maps_t *dst = ((struct {xdp_maps_t *xdp_maps; struct config *cmd; } *)args)->xdp_maps;
    struct config *config = ((struct { xdp_maps_t *xdp_maps; struct config *cmd;} *)args)->cmd;

    while (1)
    {
        for (int i = 0; i < MAX_SERVERS; i++)
        {
            if (config->servers[i].ip == NULL)
            {
                break;
            }

            a2s_query(config->servers[i].ip, config->servers[i].port, dst, 0x54); // A2S_INFO
            a2s_query(config->servers[i].ip, config->servers[i].port, dst, 0x55); // A2S_PLAYERS
        }

        sleep(2);
    }
    return;
}

int update_hash_key(xdp_maps_t *maps)
{
    // Generate a random uint8 value
    uint8_t random_value = rand() % 256; 
    int key = 0;   

    // Update the map with the random value
    if (bpf_map_update_elem(maps->hash_key, &key, &random_value, BPF_ANY) < 0)
    {
        perror("Failed to update hash_key map");
        return -1;
    }

    return 0;
}
