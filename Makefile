CC = clang

BUILDDIR = build
SRCDIR = src

LIBBPFSRC = modules/libbpf/src
LIBBPFOBJS = $(wildcard $(LIBBPFSRC)/staticobjs/*.o)

LOADERSRC = loader.c
LOADEROUT = xdpa2scache
MAPSSRC = maps.c
XDPPROGSRC = xdp.c
XDPPROGBC = xdp.bc
XDPPROGOBJ = xdp.o

LDFLAGS += -lelf -lz -lconfig -lxdp -lbpf 

all: build_xdptools libbpf loader xdp 

libbpf:
	$(MAKE) -C $(LIBBPFSRC)

loader: libbpf $(OBJS)
	mkdir -p $(BUILDDIR)/
	$(CC) $(LDFLAGS) $(INCS)  -o $(BUILDDIR)/$(LOADEROUT) $(LIBBPFOBJS) $(SRCDIR)/$(LOADERSRC) $(SRCDIR)/$(MAPSSRC) $(LIBXDP)

xdp: $(SIPHASHOBJ)
	mkdir -p $(BUILDDIR)/
	$(CC) $(INCS) -D__BPF__ -O2 -D __BPF_TRACING__ -Wno-unused-value     -Wno-pointer-sign     -Wno-compare-distinct-pointer-types  -emit-llvm -c -g -o $(BUILDDIR)/$(XDPPROGBC) $(SRCDIR)/$(XDPPROGSRC)
	llc -march=bpf -filetype=obj -o $(BUILDDIR)/$(XDPPROGOBJ) $(BUILDDIR)/$(XDPPROGBC) 

clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	rm -f $(BUILDDIR)/*.o $(BUILDDIR)/*.bc
	rm -f $(BUILDDIR)/$(LOADEROUT)

build_xdptools:
	$(MAKE) -C modules/xdp-tools/

install:
	mkdir -p /etc/xdpa2scache
	cp $(BUILDDIR)/$(XDPPROGOBJ) /etc/xdpa2scache/$(XDPPROGOBJ)
	cp $(BUILDDIR)/$(LOADEROUT) /usr/bin/$(LOADEROUT)
	cp data/xdpa2scache.service /etc/systemd/system/
	$(MAKE) install -C modules/xdp-tools/

.PHONY: libbpf all
.DEFAULT: all