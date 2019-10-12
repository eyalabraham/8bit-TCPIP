#
# IPv4 stack file list
#

# IP stack core modules
STACKCORE=$(IPDIR)/stack.c

# Microchip ENC28J60 driver and data link layer
INTERFACE=$(IPDIR)/enc28j60.c \
	$(IPDIR)/arp.c \
	$(IPDIR)/slipv25.c \
	$(IPDIR)/netif.c

# SLIP driver and data link layer for V25
INTERFACESLIPV25=$(IPDIR)/slipv25.c \
	$(IPDIR)/netif.c

# SLIP driver and data link layer for PC-XT
INTERFACESLIPSIO=$(IPDIR)/slipsio.c \
	$(IPDIR)/netif.c

# Network layer
NETWORK=$(IPDIR)/ipv4.c

# transport layer
TRANSPORT= $(IPDIR)/icmp.c \
	$(IPDIR)/udp.c \
	$(IPDIR)/tcp.c

