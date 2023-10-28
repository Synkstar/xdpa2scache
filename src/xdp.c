#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <string.h> 
#include "loader.h"
#include "maps.h"
#include "csum.h"

#define MAX_UDP_SIZE 1480

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct server_key);
    __type(value, struct a2s_val);
    __uint(max_entries, 64);
} a2s_info SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct server_key);
    __type(value, struct a2s_val);
    __uint(max_entries, 64);
} a2s_players SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u8[16]);
    __uint(max_entries, 1);
} hash_key SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u64);
    __uint(max_entries, 1);
} timestamp_map SEC(".maps");

struct four_tuple
{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

static __always_inline void swap_eth(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    memcpy(tmp, &eth->h_source, ETH_ALEN);

    memcpy(&eth->h_source, &eth->h_dest, ETH_ALEN);
    memcpy(&eth->h_dest, tmp, ETH_ALEN);
}

static __always_inline void swap_ip(struct iphdr *iph)
{
    __be32 tmp;
    memcpy(&tmp, &iph->saddr, sizeof(__be32));

    memcpy(&iph->saddr, &iph->daddr, sizeof(__be32));
    memcpy(&iph->daddr, &tmp, sizeof(__be32));
}

static __always_inline void swap_udp(struct udphdr *udph)
{
    __be16 tmp;
    memcpy(&tmp, &udph->source, sizeof(__be16));

    memcpy(&udph->source, &udph->dest, sizeof(__be16));
    memcpy(&udph->dest, &tmp, sizeof(__be16));
}

// May replace this in the future
static __always_inline uint32_t jenkins_one_at_a_time_hash(char *key, size_t len)
{
    uint32_t hash = 0;
    size_t i;
    for (i = 0; i < len; ++i)
    {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static __always_inline __u32 cookie_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
    uint8_t *value;
    uint8_t key[16];
    uint8_t out[4] = {0};
    __u32 cookie = 0;
    struct four_tuple data = {saddr, daddr, sport, dport};
    int map_key = 0;

    value = bpf_map_lookup_elem(&hash_key, &map_key);

    if (value)
    {
        memcpy(&key, value, 16);
        char hash_input[20];
        // Incorporate data from our ip header and udp header
        memcpy(hash_input, &data, sizeof(struct four_tuple));
        // Incorporate our key
        memcpy(hash_input + sizeof(struct four_tuple), key, 8);
        cookie = jenkins_one_at_a_time_hash(hash_input, 20);
    }

    return cookie;
}

static __always_inline __u32 create_cookie(struct iphdr *iph, struct udphdr *udph)
{
    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    __u16 sport = udph->source;
    __u16 dport = udph->dest;

    __u32 cookie = cookie_hash(saddr, daddr, sport, dport);

    return cookie;
}

static __always_inline bool check_cookie(struct iphdr *iph, struct udphdr *udph, __u32 check)
{
    return create_cookie(iph,udph) == check;
}

static __always_inline int send_a2s_challenge(struct xdp_md *ctx)
{
    // Reinitialize pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 len = data_end - data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
    {
        return XDP_DROP;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end)
    {
        return XDP_DROP;
    }

    struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
    if (udph + 1 > data_end)
    {
        return XDP_DROP;
    }

    __u32 challenge = create_cookie(iph, udph);
    __u8 response[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(response + 5, &challenge, 4);

    unsigned int payload_len = data_end - (data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr));

    // Adjust the size of the payload when there is a difference
    if (bpf_xdp_adjust_tail(ctx, sizeof(response) - payload_len) != 0)
    {
        return XDP_DROP;
    }

    // Ininitialize pointers again because of the tail adjustment
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    eth = data;
    if (data + sizeof(*eth) > data_end)
    {
        return XDP_DROP;
    }

    iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end)
    {
        return XDP_DROP;
    }

    udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
    if (udph + 1 > data_end)
    {
        return XDP_DROP;
    }

    len = data_end - data;
    void *payload = data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr);
    if (payload + 9 > data_end)
    {
        return XDP_DROP;
    }

    // Write the response to the packet payload
    memcpy(payload, response, sizeof(response));

    // Swap and reinitialize checksums for sending to client
    swap_eth(eth);
    swap_ip(iph);
    swap_udp(udph);

    udph->len = htons(sizeof(struct udphdr) + 9);
    udph->check = 0;
    udph->check = calc_udp_csum(iph, udph, data_end);

    __u16 old_len = iph->tot_len;
    iph->tot_len = htons(len - sizeof(struct ethhdr));
    __u8 old_ttl = iph->ttl;
    iph->ttl = 64;
    iph->check = csum_diff4(old_len, iph->tot_len, iph->check);
    iph->check = csum_diff4(old_ttl, iph->ttl, iph->check);

    return XDP_TX;
}

static __always_inline int send_a2s_data(struct xdp_md *ctx, __u8 header, struct a2s_val *val)
{
    // Reinitialize pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 len = data_end - data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
    {
        return XDP_DROP;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end)
    {
        return XDP_DROP;
    }

    struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
    if (udph + 1 > data_end)
    {
        return XDP_DROP;
    }

    // Get out payload pointer
    void *payload = data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr);
    unsigned int payload_len = data_end - (data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr));

    struct a2s_val *val_p;

    // Get the location of the cookie aka challenge
    uint32_t *cookie = payload + 5;

    // If it is an a2s_info packet the challenge is at the end of the 25 byte query
    if (header == 0x54)
    {
        cookie = payload + 25;
    }

    // Make sure we dont go out of range of the packet
    if (cookie + 1 > data_end)
    {
        return XDP_DROP;
    }

    // Validate cookie
    if (check_cookie(iph, udph, *cookie))
    {
        // Resize packet to fit payload
        if (bpf_xdp_adjust_tail(ctx, val->size - payload_len) != 0)
        {
            return XDP_DROP;
        }

        // Ininitialize pointers again because of the tail adjustment
        data_end = (void *)(long)ctx->data_end;
        data = (void *)(long)ctx->data;

        eth = data;
        if (data + sizeof(*eth) > data_end)
        {
            return XDP_DROP;
        }

        iph = data + sizeof(struct ethhdr);
        if (iph + 1 > data_end)
        {
            return XDP_DROP;
        }

        udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        if (udph + 1 > data_end)
        {
            return XDP_DROP;
        }

        len = data_end - data;
        payload = data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr);
        if (payload + 1 > data_end)
        {
            return XDP_DROP;
        }

        // Loop to write data from the map to packet payload
        for (int i = 0; i < val->size; i++)
        {
            if (payload + (i + 1) > (__u8 *)data_end)
            {
                break;
            }

            if (i >= sizeof(val->data))
            {
                break;
            }

            *((__u8 *)payload + i) = *(val->data + i);
        }

        // Swap and reinitialize checksums for sending to client
        swap_eth(eth);
        swap_ip(iph);
        swap_udp(udph);

        udph->len = htons(sizeof(struct udphdr) + val->size);
        udph->check = 0;
        udph->check = calc_udp_csum(iph, udph, data_end);

        __u16 old_len = iph->tot_len;
        iph->tot_len = htons(len - sizeof(struct ethhdr));
        __u8 old_ttl = iph->ttl;
        iph->ttl = 64;
        iph->check = csum_diff4(old_len, iph->tot_len, iph->check);
        iph->check = csum_diff4(old_ttl, iph->ttl, iph->check);

        return XDP_TX;
    }
    else
    {
        return send_a2s_challenge(ctx); 
    }
    return XDP_DROP;
}

SEC("xdpa2scache")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u16 len = data_end - data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
    {
        return XDP_DROP;
    }

    // Set our timestamp in the map. This is kind of annoying to have to do but the kernel time in the xdp program is different from in userspace
    int timestamp_index = 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&timestamp_map, &timestamp_index, &now, BPF_ANY);

    if (eth->h_proto == htons(ETH_P_IP))
    {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (iph + 1 > data_end)
        {
            return XDP_DROP;
        }

        if (iph->protocol == IPPROTO_UDP)
        {
            struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
            if (udph + 1 > data_end)
            {
                return XDP_DROP;
            }

            struct server_key key = {};
            key.ip = iph->daddr;
            key.port = udph->dest;

            void *payload = data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr);
            unsigned int payload_len = data_end - (data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr));

            if ((payload + 8 < data_end) && *((__u32 *)payload) == htonl(0xFFFFFFFF))
            {
                uint8_t type = *(uint8_t *)(payload + 4);
                struct a2s_val *val;
                switch (type)
                {
                // A2S_INFO
                case 0x54:
                    val = bpf_map_lookup_elem(&a2s_info, &key);
                    if (val)
                    {
                        if (now > val->expires)
                        {
                            bpf_map_delete_elem(&a2s_info, &key);
                            return XDP_PASS;
                        }
                        // A2S_INFO packet with challenge.
                        if (payload_len == 29)
                        {
                            return send_a2s_data(ctx, 0x54, val);
                        }

                        // A2S_INFO packet without challenge
                        if (payload_len == 25)
                        {
                            return send_a2s_challenge(ctx);
                        }
                        return XDP_DROP;
                    }
                    break;
                // A2S_PLAYERS
                case 0x55:
                    if (payload_len == 9)
                    {
                        val = bpf_map_lookup_elem(&a2s_players, &key);
                        if (val)
                        {
                            if (now > val->expires)
                            {
                                bpf_map_delete_elem(&a2s_players, &key);
                                return XDP_PASS;
                            }
                            __u32 *p = (__u32 *)(payload + 5);
                            if (*p == htonl(0x00000000))
                            {
                                return send_a2s_challenge(ctx);
                            }
                            return send_a2s_data(ctx, 0x55, val);
                        }
                    }
                    break;
                // TOTO A2S_RULES
                }
                
            }
        }
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";