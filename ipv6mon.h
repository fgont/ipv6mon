/*
 * Header file for the ip6mon tool
 *
 */

#define LUI		long unsigned int

#define BUFFER_SIZE	65556
#define SNAP_LEN	65535
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define	ETHERTYPE_IPV6	0x86dd		/* IP protocol version 6 */
#define	ETHER_ADDR_LEN	ETH_ALEN	/* size of ethernet addr */
#define	ETHER_HDR_LEN	ETH_HLEN	/* total octets in header */

#define ETHER_ADDR_PLEN	18		/* Includes termination byte */

#define ETHER_ALLNODES_LINK_ADDR	"33:33:00:00:00:01"
#define ETHER_ALLROUTERS_LINK_ADDR	"33:33:00:00:00:02"

#define	MIN_IPV6_HLEN		40
#define MIN_TCP_HLEN		20
#define MIN_UDP_HLEN		20
#define MIN_DST_OPT_HLEN	8
#define MIN_ICMP6_HLEN		8
#define	SLLA_OPT_LEN		1
#define	TLLA_OPT_LEN		1
#define MAX_TLLA_OPTION		256
#define MAX_IFACES		100	/* Max number of configured interfaces to search for */
#define IFACE_LENGTH	255

#define	PROBE_ICMP6_ECHO	1
#define PROBE_UNREC_OPT		2

#define IPV6_FILTER "ip6"
#define TCPV6_FILTER "ip6 and tcp"
#define UDPV6_FILTER "ip6 and udp"
#define ICMPV6_FILTER "icmp6"
#define ICMPV6_NA_FILTER 		"icmp6 and ip6[7]==255 and ip6[40]==136 and ip6[41]==0"
#define ICMPV6_RA_FILTER 		"icmp6 and ip6[7]==255 and ip6[40]==134 and ip6[41]==0"


/* multi_scan */
#define ICMPV6_ECHO_RESPONSE_FILTER	"icmp6 and ((ip6[40]==129 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0))"
#define ICMPV6_ERROR_FILTER		"icmp6 and ((ip6[40]==4) or (ip6[40]==135 and ip6[41]==0))"	/* ICMPv6 Parameter Problem */
#define ICMPV6_ECHO_PAYLOAD_SIZE	56

#define MAX_PREFIXES_ONLINK		100
#define MAX_PREFIXES_AUTO		100
#define	MAX_IPV6_ENTRIES		65000
#define MAX_LOCAL_ADDRESSES		256

/* Constant for the host-scanning functions */
#define	PRINT_ETHER_ADDR		1
#define NOT_PRINT_ETHER_ADDR		0


#define	VALID_MAPPING			2
#define INVALID_MAPPING			3
 


#define ALL_NODES_MULTICAST_ADDR	"FF02::1"
#define ALL_ROUTERS_MULTICAST_ADDR	"FF02::2"
#define SOLICITED_NODE_MULTICAST_PREFIX "FF02:0:0:0:0:1:FF00::"


/* Support for IPv6 extension headers */
#define FRAG_HDR_SIZE		8
#define	MAX_IPV6_PAYLOAD	65535
#define MAX_DST_OPT_HDR		256
#define MAX_DST_OPT_U_HDR	MAX_DST_OPT_HDR
#define MAX_HBH_OPT_HDR		MAX_DST_OPT_HDR


/* Filter Constants */
#define MAX_BLOCK_SRC			50
#define MAX_BLOCK_DST			50
#define MAX_BLOCK_TARGET		50
#define MAX_BLOCK_LINK_SRC		50
#define MAX_BLOCK_LINK_DST		50

#define MAX_ACCEPT_SRC			50
#define MAX_ACCEPT_DST			50
#define MAX_ACCEPT_TARGET		50
#define MAX_ACCEPT_LINK_SRC		50
#define MAX_ACCEPT_LINK_DST		50

#define ACCEPTED			1
#define BLOCKED				0

#define	ADD_ENTRY			1
#define DEL_ENTRY			2

/* Constants used with the libcap functions */
#define PCAP_SNAP_LEN			65535

/*
   pcap filter to accept: Neighbor Solicitations, Neighbor Advertisements, Router Advertisements,
   Echo Reply, and ICMPv6 Error Messages
 */
#define PCAP_IPV6MON_FILTER		"icmp6 and ((((ip6[40]==134 and ip6[41]==0) or (ip6[40]==135 and ip6[41]==0) or (ip6[40]==136 and ip6[41]==0)) and ip6[7]==255) or (ip6[40]==129 and ip6[41]==0) or (ip6[40]==4))"

#define	PCAP_TIMEOUT			1
#define	PCAP_PROMISC			1
#define	PCAP_OPT			1
#ifndef PCAP_NETMASK_UNKNOWN
	#define PCAP_NETMASK_UNKNOWN	0xffffffff
#endif


#define MAX_LIST_ENTRIES		8192
#define	MIN_ADDR_ENTRIES		100
#define	MAX_ADDR_ENTRIES		50000
#define MAX_CANDIDATE_ENTRIES		MAX_HOST_ENTRIES/8;
#define MAX_FUDGE_FACTOR		15
#define MAX_HOST_PROBES			4
#define MAX_CANDIDATE_PROBES		4
#define	MAX_UNPROBED_INTERVAL		40
#define MIN_UNICAST_PROBE_INTERVAL	10
#define UNICAST_PROBE_INTERVAL		15
#define ADDR_TIMEOUT			90
#define MIN_ADDR_TIMEOUT		30
#define MIN_CANDIDATE_TIMEOUT		30
#define CAND_ADDR_TIMEOUT		((ADDR_TIMEOUT *3) /4)
#define MC_ECHO_PROBE_INTERVAL		120
#define MIN_MC_ECHO_PROBE_INTERVAL	60
#define MC_UNREC_PROBE_INTERVAL		120
#define MIN_MC_UNREC_PROBE_INTERVAL	60
#define	SELECT_TIMEOUT			4
#define RETRY_CONFIG			60
#define RS_SEND_INTERVAL		2
#define RA_ACCEPT_WINDOW		5
#define CHECK_CONFIG_INTERVAL		60
#define LOCAL_ADDRESS_TIMEOUT		(CHECK_CONFIG_INTERVAL + RA_ACCEPT_WINDOW)
#define MAX_PROC_ENTRIES_INT		1
#define MAX_GARB_COLLECT_INT            10

/* Internal state of send_multicast */
#define	SCAN_LOCAL			1
#define SCAN_GLOBAL			2

/* Possible values for the TimestampFormat */
#define	TIMESTAMP_DATE			1
#define	TIMESTAMP_EPOCH			2

/* Constants for config file processing */
#define MAX_LINE_SIZE			250
#define MAX_VAR_NAME_LEN		40


struct ether_addr{
  u_int8_t a[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));

struct	nd_opt_slla{
    u_int8_t	type;
    u_int8_t	length;
    u_int8_t	address[6];
} __attribute__ ((__packed__));

struct	nd_opt_tlla{
    u_int8_t	type;
    u_int8_t	length;
    u_int8_t	address[6];
} __attribute__ ((__packed__));

struct ipv6pseudohdr{
    struct in6_addr srcaddr;
    struct in6_addr dstaddr;
    u_int32_t	len;
    u_int8_t zero[3];
    u_int8_t	nh;
} __attribute__ ((__packed__));

/* 10Mb/s ethernet header */
struct ether_header
{
  struct ether_addr dst;	/* destination eth addr	*/
  struct ether_addr src;	/* source ether addr	*/
  u_int16_t ether_type;		/* packet type ID field	*/
} __attribute__ ((__packed__));


struct host_entry{
	struct in6_addr		ip6;
	struct ether_addr	ether;
	unsigned char		flag;
	time_t			fseen;
	time_t			lseen;
	time_t			lprobed;
	unsigned int		nprobes;
	struct host_entry	*next;
	struct host_entry	*prev;
	unsigned int		ffactor;
};

struct host_list{
	struct host_entry	**host;			/* Double-linked list of host entries */
	unsigned int		nhosts;			/* Current number of host entries */
	unsigned int		maxhosts;		/* Maximum number of host entries */
	unsigned int		ncandidates;		/* Candidate addresses in list */
	unsigned int		maxcandidates;		/* Maximum number of candidate entries */
	time_t			lastprocessed;		/* Last time the list was processed entirely */
	time_t			lastgcollection;		/* Last time the list was garbage-collected */

	u_int16_t		key_l;			/* Low-order word of the hash key */
	u_int16_t		key_h;			/* High-order word of the hash key */

	unsigned int 		mc_unrec_probe_f;	/* Whether Unrec probes should be sent */
	unsigned int		mc_unrec_state;		/* Multicast unrec probe state (local vs. global) */
	unsigned int		mc_unrec_naddr;		/* Current src addr for mcast echo probes   */
	u_int16_t		mc_unrec_seq;		/* Multicast unrec sequence #	*/
	time_t			mc_unrec_last;		/* Last multicast unrec probe	*/

	unsigned int		mc_echo_probe_f;	/* Whether Echo probes should be sent */
	unsigned int		mc_echo_state;		/* Multicast echo probe state (local vs. global) */
	unsigned int		mc_echo_naddr;		/* Current src addr for mcast echo probes   */
	unsigned int		mc_echo_seq;		/* Multicast echo sequence #	*/
	time_t			mc_echo_last;		/* Last multicast echo probe	*/

	unsigned int		np_key;			/* Next list entry to process	*/
	struct host_entry	*np_hentry;		/* Next host entry to process	*/
};

struct prefix_entry{
	struct in6_addr		ip6;
	unsigned char		len;
	time_t			tstamp;
};

struct prefix_list{
	struct prefix_entry	**prefix;
	unsigned int		nprefix;
	unsigned int		maxprefix;
};


struct address_list{
	struct in6_addr		*addr;
	unsigned int		naddr;
	unsigned int		maxaddr;
};

struct iface_data{
	char			iface[IFACE_LENGTH];
	struct ether_addr	ether;
	unsigned int		ether_flag;
	struct in6_addr		ip6_local;
	unsigned int		ip6_local_flag;
	struct prefix_list	ip6_global;
	unsigned int		ip6_global_flag;
	unsigned int		ip6_global_nconfig;
	time_t			ip6_global_conftime;
	time_t			ip6_global_lastcheck;
	time_t			last_rs;
	struct in6_addr		router_ip6;
	struct ether_addr	router_ether;
	struct prefix_list	prefix_ac;
	struct prefix_list	prefix_ol;
	unsigned int		local_retrans;
	unsigned int		local_timeout;
	unsigned int		mtu;
	unsigned int		pending_write_f;
	void			*pending_write_data;
	unsigned int		pending_write_size;
	int			fd;
	fd_set			*rset;
	fd_set			*wset;
	fd_set			*eset;
	unsigned int		write_errors;
};


#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
    #ifndef s6_addr16
	    #define s6_addr16	__u6_addr.__u6_addr16
    #endif

    #ifndef s6_addr8
	    #define s6_addr8	__u6_addr.__u6_addr8
    #endif

    #ifndef s6_addr32
	    #define s6_addr32	__u6_addr.__u6_addr32
    #endif
#endif


/* This causes Linux to use the BSD definition of the TCP and UDP header fields */
#ifndef __FAVOR_BSD
	#define __FAVOR_BSD
#endif

