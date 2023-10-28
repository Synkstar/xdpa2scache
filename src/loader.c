#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <signal.h>
#include <pthread.h>
#include <libconfig.h>
#include <xdp/libxdp.h>
#include "loader.h"
#include "maps.h"

// Global variables
char *interface;
int ifidx;
struct xdp_program *prog;

void parse_config_file(struct config *cfg, const char *filename)
{
    config_t config;
    config_init(&config);

    if (!config_read_file(&config, filename))
    {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&config),
                config_error_line(&config), config_error_text(&config));
        config_destroy(&config);
        exit(EXIT_FAILURE);
    }

    const char *interface_temp;
    if (config_lookup_string(&config, "interface", &interface_temp) != CONFIG_TRUE)
    {
        fprintf(stderr, "No 'interface' setting in configuration file.\n");
        exit(EXIT_FAILURE);
    }
    cfg->interface = strdup(interface_temp);

    config_setting_t *servers = config_lookup(&config, "servers");
    if (servers == NULL)
    {
        fprintf(stderr, "No 'servers' setting in configuration file.\n");
        exit(EXIT_FAILURE);
    }

    int count = config_setting_length(servers);
    for (int i = 0; i < count; ++i)
    {
        config_setting_t *server = config_setting_get_elem(servers, i);

        const char *ip_temp;
        int port;
        if (!(config_setting_lookup_string(server, "ip", &ip_temp) && config_setting_lookup_int(server, "port", &port)))
        {
            fprintf(stderr, "Invalid 'server' setting at index %d.\n", i);
            exit(EXIT_FAILURE);
        }

        cfg->servers[i].ip = strdup(ip_temp);
        cfg->servers[i].port = port;
    }

    // XDP configs
    int offload;
    config_lookup_int(&config, "offload", &offload);
    cfg->offload = offload;

    int skb;
    config_lookup_int(&config, "skb", &skb);
    cfg->skb = skb;

    config_destroy(&config);
}

void parse_cmd(struct config *cfg, int argc, char **argv)
{
    int opt;
    extern char *optarg;
    char *config_file_path = "/etc/xdpa2scache/config";
    while ((opt = getopt(argc, argv, "c:")) != -1)
    {
        switch (opt)
        {
        case 'c':
            config_file_path = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s -i <interface> [-c <config_file_path>]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    parse_config_file(cfg, config_file_path);
}

struct xdp_program *load_bpf_object(const char *filename, __u8 offload, int ifidx)
{
    struct xdp_program *prog;

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    opts.relaxed_maps = true;
    opts.pin_root_path = "/sys/fs/bpf";
    opts.attach_prog_fd = -1;
    opts.kconfig = NULL;
    prog = xdp_program__open_file(filename, NULL, &opts);
    if (!prog)
    {
        fprintf(stderr, "ERROR: failed to load bpf object file: %s\n", strerror(errno));
        return NULL;
    }

    return prog;
}

int attach_xdp(int ifidx, struct xdp_program *prog, struct config *cmd)
{
    int err;
    if (cmd->offload)
    {
        err = xdp_program__attach(prog, ifidx, cmd->skb ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_HW_MODE, 0);
    }
    else
    {
        err = xdp_program__attach(prog, ifidx, cmd->skb ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, 0);
    }
    if (err < 0)
    {
        fprintf(stderr, "ERROR: failed to attach program to interface: %s\n", strerror(-err));
        return -1;
    }
    return 0;
}

int detach_xdp(int ifidx, struct xdp_program *prog)
{
    int err;

    err = xdp_program__detach(prog, ifidx, 0, 0);
    if (err < 0)
    {
        fprintf(stderr, "ERROR: failed to detach program from interface: %s\n", strerror(-err));
        return -1;
    }
    return 0;
}

void sigint_handler(int sig_num)
{
    signal(SIGINT, sigint_handler);
    if (detach_xdp(ifidx, prog) < 0)
    {
        fprintf(stderr, "ERROR: failed to detach xdp program from interface\n");
    }
    xdp_program__close(prog);
    exit(0);
}

int main(int argc, char **argv)
{
    struct config cmd = {0};
    parse_cmd(&cmd, argc, argv);
    interface = cmd.interface;
    ifidx = if_nametoindex(interface);
    if (ifidx == 0)
    {
        fprintf(stderr, "ERROR: failed to get interface index: %s\n", strerror(errno));
        return -1;
    }

    prog = load_bpf_object("/etc/xdpa2scache/xdp.o", cmd.offload, ifidx);
    if (prog == NULL)
    {
        fprintf(stderr, "ERROR: failed to load bpf object file\n");
        return -1;
    }

    if (attach_xdp(ifidx, prog, &cmd) < 0)
    {
        fprintf(stderr, "ERROR: failed to attach program to interface\n");
        return -1;
    }

    // GCreate an xdpmaps pointer
    xdp_maps_t xdp_maps;

    // Get our maps from the xdp program into our userspace program.
    get_maps(prog, &xdp_maps);

    // Set a random key used for the hash function
    update_hash_key(&xdp_maps);

    // Hook sigint for gacefully removing the program
    signal(SIGINT, sigint_handler);

    // Create a thread for gathering from the server
    pthread_t thread_id;
    struct
    {
        xdp_maps_t *xdp_maps;
        struct config *cmd;
    } args = {&xdp_maps, &cmd};
    if (pthread_create(&thread_id, NULL, (void *)gather_from_servers, &args) != 0)
    {
        fprintf(stderr, "ERROR: failed to create thread\n");
        return -1;
    }

    // Keep the program running
    pause();

    return 0;
}
