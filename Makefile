# Makefile for ipset_test_server
#
# Detects libtirpc (modern distros) vs libnsl (legacy glibc).
# Usage:
#   make              — build all binaries
#   make install      — install binaries + systemd unit
#   make clean

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Wno-unused-parameter -g

# ── ipset binary detection ───────────────────────────────────────────────────
IPSET_BIN = $(shell command -v ipset)

ifeq ($(IPSET_BIN),)
	$(error ipset binary not found. Install ipset package)
endif

CFLAGS += -DIPSET_PATH=\"$(IPSET_BIN)\"

# ── RPC library auto-detection ────────────────────────────────────────────────
TIRPC_INC = /usr/include/tirpc
TIRPC_LIB = -ltirpc

ifeq ($(shell test -f $(TIRPC_INC)/rpc/rpc.h && echo yes), yes)
	# Modern: libtirpc
	RPC_INC = -I$(TIRPC_INC)
	RPC_LIB = $(TIRPC_LIB)
else ifeq ($(shell test -f /usr/include/rpc/rpc.h && echo yes), yes)
	# Legacy: glibc built-in ONC RPC
	RPC_INC =
	RPC_LIB = -lnsl
else
	$(error ONC RPC headers not found. \
		Install libtirpc-dev (Debian/Ubuntu) or libtirpc-devel (RHEL/Fedora))
endif

CFLAGS  += $(RPC_INC)
LDFLAGS  = $(RPC_LIB)

# ── Targets ──────────────────────────────────────────────────────────────────
SERVER_TARGET = ipset_test_server
PING_TARGET   = ipset_test_ping

# ── Sources ──────────────────────────────────────────────────────────────────
SERVER_SRCS = \
	ipset_test_server.c \
	ipset_test_rpc_xdr.c

PING_SRCS = \
	ipset_test_ping.c \
	ipset_test_rpc_clnt.c \
	ipset_test_rpc_xdr.c

SERVER_OBJS = $(SERVER_SRCS:.c=.o)
PING_OBJS   = $(PING_SRCS:.c=.o)

# ── Rules ────────────────────────────────────────────────────────────────────
.PHONY: all clean install uninstall

all: $(SERVER_TARGET) $(PING_TARGET)

$(SERVER_TARGET): $(SERVER_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(PING_TARGET): $(PING_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SERVER_OBJS) $(PING_OBJS)
	rm -f $(SERVER_TARGET) $(PING_TARGET)

# ── Install ──────────────────────────────────────────────────────────────────
INSTALL_BIN  = /usr/local/sbin
INSTALL_UNIT = /etc/systemd/system

install: all
	install -m 755 $(SERVER_TARGET) $(INSTALL_BIN)/
	install -m 755 $(PING_TARGET)   $(INSTALL_BIN)/
	install -m 644 ipset_test_server.service $(INSTALL_UNIT)/
	systemctl daemon-reload
	systemctl enable ipset_test_server
	systemctl start ipset_test_server
	@echo ""
	@echo "Installed:"
	@echo "  $(INSTALL_BIN)/$(SERVER_TARGET)"
	@echo "  $(INSTALL_BIN)/$(PING_TARGET)"
	@echo ""
	@echo "Service installed and started."
	@echo "Check status: systemctl status ipset_test_server"

uninstall:
	systemctl stop ipset_test_server || true
	systemctl disable ipset_test_server || true
	rm -f $(INSTALL_UNIT)/ipset_test_server.service
	rm -f $(INSTALL_BIN)/$(SERVER_TARGET)
	rm -f $(INSTALL_BIN)/$(PING_TARGET)
	systemctl daemon-reload
