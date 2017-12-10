#
# IPv4 stack file list
#

# IP stack core modules
STACKCORE=$(IPDIR)/stack.c

# Microchip ENC28J60 driver and data link layer
INTERFACE=$(IPDIR)/enc28j60.c \
	$(IPDIR)/arp.c \
	$(IPDIR)/slip.c \
	$(IPDIR)/netif.c

# Network layer
NETWORK=$(IPDIR)/ipv4.c

# transport layer
TRANSPORT= $(IPDIR)/icmp.c \
	$(IPDIR)/udp.c \
	$(IPDIR)/tcp.c

# application layer
APPLICATION=$(IPDIR)/ntp.c \
	$(IPDIR)/http.c \
	$(IPDIR)/dhcp.c \
	$(IPDIR)/ping.c

IPSTACK=$(STACKCORE) \
	$(INTERFACE) \
	$(NETWORK) \
	$(TRANSPORT) \
	$(APPLICATION)
