#pragma once
struct config
{
    char *interface;
    unsigned int offload : 1;
    unsigned int skb : 1;
    __u32 xdp_flags;
    __u32 xsk_bind_flags;
    int xsk_if_queue;
    int xsk_map_fd;
    int ifindex;
    int xsk_poll_mode;
    struct server
    {
        char *ip;
        int port;
    } servers[10];
};