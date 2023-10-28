# XDP A2S Cache

Currently only supports A2S_INFO and A2S_PLAYERS. Purely done in XDP at the moment AF_XDP will have to be added to support A2S_RULES and large A2S_PLAYERS because of fragmentation.
Tested on kernel version 6.1.0-12 ( Debian 11 ). Keep in mind older kernel versions can be lacking in capabilities for XDP.

## Installation:
```
git clone https://github.com/Synkstar/xdpa2scache.git --recursive

sudo apt install build-essential make clang llvm m4 libpcap-dev libelf-dev gcc-multilib cmake

cd xdpa2scache

make

sudo make install

# Edit configuration at /etc/xdpa2scache/config

systemctl enable --now xdpa2scache.service 
```

Todo needed for production use:
```
1. AF_XDP for A2S_PLAYERS and A2S_RULES
```

## Why did I make this ?
A long time ago I used a regular a2s cache program for my game servers but those are slow and this could do millions of packets per second on a single cpu core.
Personally I'd recommend something like this for games that blacklist servers for using a2s caching by an anycasted ddos mitigation provider.
IE Unturned etc.


