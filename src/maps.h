#include <linux/types.h>

#define MAX_A2S_SIZE 1400
#define MAX_SERVERS 1000
#define A2S_EXPIRES 10

typedef struct xdp_maps
{
    int xsks_map;
    int a2s_players;
    int a2s_info;
    int hash_key;
    int timestamp;
} xdp_maps_t;

struct a2s_val
{
    __u64 size;
    __u64 expires;
    unsigned char data[MAX_A2S_SIZE];
};

struct server_key
{
    __be32 ip;
    __be16 port;
};

struct key_value_pair
{
    struct server_key key;
    struct a2s_val value;
};

struct xdp_program;
struct config;

void get_maps(struct xdp_program *, xdp_maps_t *);

int update_hash_key(xdp_maps_t *);

void gather_from_servers(void *);
