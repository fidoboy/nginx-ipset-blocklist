# Makefile for ipset_test_server
#
# Detects libtirpc (modern distros) vs libnsl (legacy glibc).
# Usage:
#   make              — build the server binary
#   make install      — install binary + systemd unit
#   make clean

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Wno-unused-parameter -g

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

# ── Sources ───────────────────────────────────────────────────────────────────
SERVER_SRCS = ipset_test_server.c \
              ipset_test_rpc_xdr.c

SERVER_OBJS = $(SERVER_SRCS:.c=.o)
TARGET      = ipset_test_server

# ── Rules ─────────────────────────────────────────────────────────────────────
.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SERVER_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "Built: $(TARGET)"
	@echo "Run:   sudo ./$(TARGET)"
	@echo "       (must run before nginx starts)"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SERVER_OBJS) $(TARGET)

# ── Install ───────────────────────────────────────────────────────────────────
INSTALL_BIN  = /usr/local/sbin
INSTALL_UNIT = /etc/systemd/system

install: $(TARGET)
	install -m 755 $(TARGET) $(INSTALL_BIN)/$(TARGET)
	install -m 644 ipset_test_server.service $(INSTALL_UNIT)/
	systemctl daemon-reload
	systemctl enable ipset_test_server
	systemctl start  ipset_test_server
	@echo "Service installed and started."
	@echo "Check status: systemctl status ipset_test_server"

uninstall:
	systemctl stop    ipset_test_server || true
	systemctl disable ipset_test_server || true
	rm -f $(INSTALL_UNIT)/ipset_test_server.service
	rm -f $(INSTALL_BIN)/$(TARGET)
	systemctl daemon-reload
