/*
 * ipv6mon v1.0: An IPv6 Address Monitoring Tool
 *
 * Copyright (C) 2011-2012 Fernando Gont
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * 
 * Build with: gcc ipv6mon.c -Wall -lpcap -o ipv6mon
 * 
 * This program has been tested to compile and run on: FreeBSD 9.0, 
 * NetBSD 5.1, OpenBSD 4.9, and Linux 2.6.38-10. It requires that the
 * libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <setjmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#include <sys/param.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <netpacket/packet.h>
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	#include <net/if_dl.h>
#endif
#include <syslog.h>
#include "ipv6mon.h"

/* Function prototypes */
int				init_iface_data(struct iface_data *);
int				init_host_list(struct host_list *);
int				insert_pad_opt(unsigned char *ptrhdr, const unsigned char *, unsigned int);
void			usage(void);
void			print_help(void);
int				ether_pton(const char *, struct ether_addr *, unsigned int);
int				ether_ntop(const struct ether_addr *, char *, size_t);
u_int16_t		in_chksum(void *, void *, size_t);
unsigned int	match_ipv6(struct in6_addr *, u_int8_t *, unsigned int, struct in6_addr *);
unsigned int	match_ether(struct ether_addr *, unsigned int, struct ether_addr *);
void			sanitize_ipv6_prefix(struct in6_addr *, u_int8_t);
void			randomize_ipv6_addr(struct in6_addr *, struct in6_addr *, u_int8_t);
void			randomize_ether_addr(struct ether_addr *);
void 			ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr);
void			generate_slaac_address(struct in6_addr *, struct ether_addr *, struct in6_addr *);
int				is_eq_in6_addr(struct in6_addr *, struct in6_addr *);
struct in6_addr		solicited_node(const struct in6_addr *);
struct ether_addr	ether_multicast(const struct in6_addr *);
int				match_ipv6_to_prefixes(struct in6_addr *, struct in6_addr *, unsigned char *, unsigned int);
int				process_router_advert(struct iface_data *, struct pcap_pkthdr *, const u_char *);
int 			validate_host_entries(pcap_t *, struct iface_data *, struct host_list *, struct host_list *);
int 			create_candidate_andress(struct iface_data *, struct host_list *, struct host_entry *);
void			free_host_entries(struct host_list *);
int				send_multicast_probe(pcap_t *, struct iface_data *, struct host_list *, unsigned char);
int				probe_node_nd(const char *, struct ether_addr *, struct in6_addr *, struct in6_addr *,\
										struct ether_addr *);
struct host_entry *is_ip6_in_list(struct host_list *, struct in6_addr *);
int				is_ip6_in_prefix_list(struct in6_addr *, struct prefix_list *);
int				is_ip6_in_address_list(struct prefix_list *, struct in6_addr *);
struct prefix_entry *lookup_ip6_in_address_list(struct prefix_list *, struct in6_addr *);
int 			send_neighbor_advert(struct iface_data *, pcap_t *,  const u_char *);
int				send_router_solicit(pcap_t *, struct iface_data *);
int				process_icmp6_response(struct iface_data *, struct host_list *, unsigned char , \
										struct pcap_pkthdr *, const u_char *, unsigned char *);
int 			valid_icmp6_response(struct iface_data *, struct host_list *, struct pcap_pkthdr *, const u_char *);
int 			process_host_entries(pcap_t *, struct iface_data *, struct host_list *);
int				get_if_addrs(struct iface_data *);
int				check_local_addresses(struct iface_data *);
int				send_host_probe(pcap_t *, struct iface_data *, unsigned char, struct host_entry *);
int				gcollection_host_entries(struct iface_data *, struct host_list *);
struct host_entry	*add_host_entry(struct host_list *, struct in6_addr *, struct ether_addr *);
int				log_hentry(struct iface_data *, struct host_entry *, time_t *, unsigned char);
u_int16_t		key(struct host_list *, struct in6_addr *);
struct in6_addr *src_addr_sel(struct iface_data *, struct in6_addr *);
int				keyval(char *, unsigned int, char **, char **);
int				process_config_file(const char *);
int				make_daemon(void);
int				already_running(void);
int				log_start(struct iface_data *);
int				log_stop(struct iface_data *);
void			sigterm(int);

/* Host list */
struct host_list	hlist;

/* Used for router discovery */
struct iface_data	idata;
struct prefix_entry	*prefix_ols[MAX_PREFIXES_ONLINK], *prefix_acs[MAX_PREFIXES_AUTO];
struct prefix_entry	*prefix_local[MAX_LOCAL_ADDRESSES];

/* Variables used for learning the default router */
struct ether_addr		router_ether, rs_ether;
struct in6_addr			router_ipv6, rs_ipv6;

/* Data structures for packets read from the wire */
pcap_t				*sfd;
struct pcap_pkthdr	*pkthdr;
const u_char		*pktdata;
unsigned char		*pkt_end;
struct ether_header	*pkt_ether;
struct ip6_hdr		*pkt_ipv6;
struct in6_addr		*pkt_ipv6addr;
unsigned int		pktbytes;

struct bpf_program	pcap_filter;
char 				dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char		buffer[BUFFER_SIZE], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
unsigned char		wbuffer[BUFFER_SIZE];
unsigned char		*v6buffer, *ptr, *startofprefixes;
char				*pref;
char 				iface[IFACE_LENGTH];
    
struct ip6_hdr		*ipv6;
struct icmp6_hdr	*icmp6;

struct ether_header	*ethernet;
struct ether_addr	hsrcaddr, hdstaddr;

struct in6_addr		srcaddr, dstaddr;

char				*lasts, *rpref;
char				*charptr;

size_t				nw;
unsigned long		ul_res, ul_val;
unsigned int		i, j, startrand;
unsigned int		skip;
unsigned char		srcpreflen;

u_int16_t			mask;
u_int8_t			hoplimit;

char 				plinkaddr[ETHER_ADDR_PLEN];
char 				psrcaddr[INET6_ADDRSTRLEN], pdstaddr[INET6_ADDRSTRLEN], pv6addr[INET6_ADDRSTRLEN];
unsigned char 		verbose_f=0, iface_f=0, hsrcaddr_f=0, probe_echo_f=0, probe_unrec_f=0, probe_f=0;
unsigned char		*prev_nh;

/* Configuration variables */
char				*logfile, *lockfile, *unprivuser, *unprivgroup, *probestr, *configfile;
unsigned int		timestampf, maxaddrentries, maxcandentries, addrtimeout, candaddrtimeout, maxunprobedint;
unsigned int		unicastprobeint, mcechoprobeint, mcunrecprobeint;

unsigned char		logfile_f=0, lockfile_f=0, unprivuser_f=0, unprivgroup_f=0, probetype_f=0, timestampf_f=0;
unsigned char		maxaddrentries_f=0, maxcandentries_f=0, addrtimeout_f=0, candaddrtimeout_f=0;
unsigned char		maxunprobedint_f=0, unicastprobeint_f=0, mcechoprobeint_f=0, mcunrecprobeint_f=0;
unsigned char		configfile_f=0, showconfig_f=0, shutdown_f=0;

/* For the log file */
FILE				*fplog;

/* Used to store the all-nodes onlink address */
struct in6_addr		all_nodes_onlink;

/* For I/O multiplexing */
fd_set				rset, wset, eset;

/* Current time */
	time_t				curtime;

int main(int argc, char **argv){
	extern char			*optarg;	
	extern int			optind;
	struct passwd		*pwdptr;
	struct group		*grpptr;
	fd_set				sset;
	int					sel;
	struct timeval		timeout;
	int					result;
	struct sigaction	sa;
	unsigned char		error_f=0;
	struct host_entry	*hptr;
	struct ether_header *pkt_ether;
	struct ip6_hdr		*pkt_ipv6;
	struct icmp6_hdr	*pkt_icmp6;
	struct nd_neighbor_solicit *pkt_ns;
	unsigned char		*pkt_end;

	static struct option longopts[] = {
		{"config-file", required_argument, 0, 'c'},
		{"show-config", no_argument, 0, 'q'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'}
	};

	char shortopts[]= "c:qvh";

	char option;

	hoplimit=255;

	while((option=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1){
		switch(option) {
			case 'c':	/* Configuration file */
				if( (configfile= malloc(strlen(optarg)+1)) == NULL){
					error_f=1;
					break;
				}

				strncpy(configfile, optarg, strlen(optarg)+1);
				configfile_f=1;
				break;			

			case 'q':
				showconfig_f=1;
				break;

			case 'v':	/* Be verbose */
				verbose_f++;
				break;
		
			case 'h':	/* Help */
				print_help();
				exit(1);
				break;

			default:
				usage();
				exit(1);
				break;
		
		} /* switch */
	} /* while(getopt) */

	if(!showconfig_f)
		openlog("ipv6mon", LOG_CONS, LOG_DAEMON);

	if(error_f){
		if(showconfig_f)
			puts("Error while allocating memory to store configuration file pathname");
		else
			syslog(LOG_ERR, "Error while allocating memory to store configuration file pathname");

		exit(1);
	}

	if(geteuid()) {
		if(showconfig_f)
			puts("ipv6mon needs superuser privileges to run");
		else
			syslog(LOG_ERR, "ipv6mon needs superuser privileges to run");

		exit(1);
	}

	if(!configfile_f){
		configfile="/etc/ipv6mon.conf";
	}

	if(process_config_file(configfile) == -1)
		exit(1);

	if(init_iface_data(&idata) != 0){
		if(showconfig_f)
			puts("Error initializing internal idata structure");
		else
			syslog(LOG_ERR, "Error initializing internal idata structure");

		exit(1);
	}

	if(init_host_list(&hlist) !=0){
		if(showconfig_f)
			puts("Error initializing internal host_list structure");
		else
			syslog(LOG_ERR, "Error initializing internal host_list structure");

		exit(1);
	}

	if(!iface_f){
		if(showconfig_f)
			puts("Must specify the network interface with the 'NetworkInterface' variable");
		else
			syslog(LOG_ERR, "Network Interface card not specified");

		exit(1);
	}

	if(showconfig_f){
		if(probe_echo_f){
			if(probe_unrec_f)
				probestr="all";
			else
				probestr="echo";
		}
		else
			probestr="unrec";

		printf("NetworkInterface: %s\n", idata.iface);
		printf("AddressLogFile: %s\n", logfile);
		printf("LockFile: %s\n", lockfile);
		printf("UnprivilegedUser: %s\n", unprivuser);
		printf("UnprivilegedGroup: %s\n", unprivgroup);
		printf("TimestampFormat: %s\n", (timestampf==TIMESTAMP_DATE)?"date":"epoch");
		printf("MaxAddressEntries: %u\n", maxaddrentries);
		printf("MaxCandidateEntries: %u\n", maxcandentries);
		printf("AddressTimeout: %u\n", addrtimeout);
		printf("CandidateAddressTimeout: %u\n", candaddrtimeout);
		printf("MaxUnprobedInterval: %u\n", maxunprobedint);
		printf("UnicastProbeInterval: %u\n", unicastprobeint);
		printf("McastEchoProbeInterval: %u\n", mcechoprobeint);
		printf("McastUnrecProbeInterval: %u\n", mcunrecprobeint);
		printf("ProbeType: %s\n", probestr);
		exit(0);
	}

	/*
	   We close the file descriptor for syslog. make_daemon() will close all open descriptors, and open
	   a new one for syslog()
	 */
	closelog();

	if(make_daemon() == -1){
		syslog(LOG_ERR, "Failed when trying to become daemon");
		exit(1);
	}

	if( (result=already_running()) == 1){
		syslog(LOG_ERR, "Another instance of ipv6mon is already running");
		exit(5);
	}
	else if(result == -1){
		syslog(LOG_ERR, "Error in already running():");
		exit(1);
	}

	/* Log file should be rw for the owner, readable by the group, with no access to others */
	umask(S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);

	if( (fplog=fopen(logfile, "a")) == NULL){
		syslog(LOG_ERR, "Error opening logfile (%m)");
		exit(1);
	}

	if( (sfd= pcap_open_live(idata.iface, PCAP_SNAP_LEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf)) == NULL){
		syslog(LOG_ERR, "Opening pcap device: %s", errbuf);
		return(-1);
	}

	if( pcap_datalink(sfd) != DLT_EN10MB){
		syslog(LOG_ERR, "Interface '%s' is not of supported interface types", iface);
		return(-1);
	}

	/* 
	   We to setuid() to UnprivilegedUser, and setgid to UnprivilegedGroup, thus releasing superuser 
	   privileges.
	 */
	if((grpptr=getgrnam(unprivgroup)) != NULL){
		if(!grpptr->gr_gid){
			syslog(LOG_ERR, "Group %s has incorrect privileges", unprivuser);
			exit(1);
		}

		if(setgid(grpptr->gr_gid) == -1){
			syslog(LOG_ERR, "Error while releasing superuser privileges (changing to group '%s')", unprivgroup);
			exit(1);
		}
	}
	else{
		syslog(LOG_ERR, "Error while releasing superuser privileges (group '%s' does not exist)", unprivgroup);
		exit(1);
	}


	if((pwdptr=getpwnam(unprivuser))){
		if(!pwdptr->pw_uid || !pwdptr->pw_gid){
			syslog(LOG_ERR, "User %s has incorrect privileges", unprivuser);
			exit(1);
		}

		if(setuid(pwdptr->pw_uid) == -1){
			syslog(LOG_ERR, "Error while releasing superuser privileges (changing to user '%s')", unprivuser);
			exit(1);
		}
	}
	else{
		syslog(LOG_ERR, "Error while releasing superuser privileges (user '%s' does not exist)", unprivuser);
		exit(1);
	}


	if(pcap_compile(sfd, &pcap_filter, PCAP_IPV6MON_FILTER, PCAP_OPT, PCAP_NETMASK_UNKNOWN) == -1){
		syslog(LOG_ERR, "pcap_compile(): %s", pcap_geterr(sfd));
		exit(1);
	}
    
	if(pcap_setfilter(sfd, &pcap_filter) == -1){
		syslog(LOG_ERR, "pcap_setfilter(): %s", pcap_geterr(sfd));
		exit(1);
	}

	pcap_freecode(&pcap_filter);

	srand(time(NULL));

	hlist.mc_unrec_probe_f= probe_unrec_f;
	hlist.mc_echo_probe_f= probe_echo_f;

	if(get_if_addrs(&idata) == -1){
		syslog(LOG_ERR, "Error in get_if_addrs()");
		exit(1);
	}

	if(!idata.ether_flag){
		randomize_ether_addr(&idata.ether);
		idata.ether_flag=1;
	}

	if(!idata.ip6_local_flag){
		ether_to_ipv6_linklocal(&idata.ether, &idata.ip6_local);
		idata.ip6_local_flag=1;
	}

	if ( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &all_nodes_onlink) <= 0){
		syslog(LOG_ERR, "Error when converting all-nodes online multicast to binary format");
		exit(1);
	}

	idata.mtu= ETH_DATA_LEN;

	idata.ip6_global_conftime= time(NULL);
	idata.ip6_global_lastcheck= time(NULL);

	if( (idata.fd= pcap_fileno(sfd)) == -1){
		syslog(LOG_ERR, "Error obtaining descriptor number for pcap_t");
		exit(1);
	}

	FD_ZERO(&sset);
	FD_SET(idata.fd, &sset);

	/* Catch SIGTERM so that we can do a clean shutdown */
	sa.sa_handler = sigterm;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGTERM, &sa, NULL) < 0){
		if(verbose_f)
			syslog(LOG_ERR, "Error while setting handler for SIGTERM");

		exit(1);
	}

	/* Write the initialization notice to the log file */
	if(log_start(&idata) == -1){
		syslog(LOG_ERR, "Error while writing to log file");
		exit(1);
	}

	while(1){
		rset= sset;
		wset= sset;
		eset= sset;

		timeout.tv_usec=0;
		timeout.tv_sec= SELECT_TIMEOUT;

		if(shutdown_f){
			if(log_stop(&idata) == -1){
				syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
				exit(1);
			}

			exit(0);
		}
			
		/*
		    Check for readability and exceptions. We only check for writeability if there is pending data
		    to send (the pcap descriptor will usually be writeable!).
		 */
		if((sel=select(idata.fd+1, &rset, (idata.pending_write_f?&wset:NULL), &eset, &timeout)) == -1){
			if(errno == EINTR){
				continue;
			}
			else{
				syslog(LOG_ERR, "Error in select() loop (%m)");

				if(log_stop(&idata) == -1){
					syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
				}

				exit(1);
			}
		}

		curtime = time(NULL);

		if(sel == 0 && (curtime-hlist.lastgcollection) > MAX_GARB_COLLECT_INT && \
												(curtime-hlist.lastprocessed) >  MAX_GARB_COLLECT_INT){
			if(gcollection_host_entries(&idata, &hlist) == -1){
				syslog(LOG_ERR, "Error while doing garbage collection");

				if(log_stop(&idata) == -1){
					syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
				}

				exit(1);
			}

			hlist.lastgcollection=curtime;
		}

		/*
		   If we didn't check for writeability in the previous call to select(), we must do it now. Otherwise, we might
		   block when trying to send a packet.
		 */
		if(!idata.pending_write_f){
			wset= sset;

			timeout.tv_usec=0;
			timeout.tv_sec= 0;

			if( (sel=select(idata.fd+1, NULL, &wset, NULL, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					syslog(LOG_ERR, "Error in select() loop (%m)");

					if(log_stop(&idata) == -1){
						syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
					}

					exit(1);
				}
			}
		}

		if( (idata.ip6_global_flag == VALID_MAPPING) && \
					(curtime - idata.ip6_global_lastcheck) >= LOCAL_ADDRESS_TIMEOUT){

			if(check_local_addresses(&idata) == -1){
				syslog(LOG_ERR, "Error in check_local_addresses()");
				exit(1);
			}
		}

		/* If we had not configured any global address, retry now */
		if( (idata.ip6_global_flag != VALID_MAPPING) && ((curtime - idata.ip6_global_conftime) >= RETRY_CONFIG)){
				if(get_if_addrs(&idata) == -1){
					syslog(LOG_ERR, "Error in get_if_addrs()");
					exit(1);
				}
	
				idata.ip6_global_conftime= curtime;
		}

		if(FD_ISSET(idata.fd, &wset)){
			curtime = time(NULL);

			if(idata.pending_write_f){
				/* There was something to send from a previous iteration, but there was no space left in the
					send buffer
				 */

				if((nw=pcap_inject(sfd, idata.pending_write_data, idata.pending_write_size)) < 0){
					syslog(LOG_ERR, "Error injecting packet in main loop: pcap_inject(): %s", \
									pcap_geterr(sfd));

					if(log_stop(&idata) == -1){
						syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
					}

					exit(1);
				}

				if(nw != idata.pending_write_size){
					if(verbose_f)
						syslog(LOG_ERR, "pcap_inject(): only wrote %lu bytes "
								"(rather than %lu bytes)\n", (LUI) nw, \
								(LUI) (idata.pending_write_size));

					idata.write_errors++;

					if(idata.write_errors > 10){
						syslog(LOG_ERR, "Too many write errors");

						if(log_stop(&idata) == -1){
							syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
						}

						exit(1);
					}
				}

				idata.pending_write_f=0;
				idata.write_errors=0;
			}

			else if( (( (idata.ip6_global.nprefix - idata.ip6_global_nconfig) && \
				((curtime - idata.ip6_global_lastcheck) >= CHECK_CONFIG_INTERVAL)) ||
				((curtime - idata.ip6_global_conftime) < RA_ACCEPT_WINDOW)) && \
				((curtime - idata.last_rs) >= RS_SEND_INTERVAL)){

				idata.last_rs=curtime;
			
				if(send_router_solicit(sfd, &idata) == -1){
					syslog(LOG_ERR, "Error sending Router Solicitation message");

					if(log_stop(&idata) == -1){
						syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
					}

					exit(1);
				}
			}

			else if( hlist.mc_echo_probe_f && ((curtime - hlist.mc_echo_last) >= mcechoprobeint)){
				hlist.mc_echo_last= curtime;

				if(send_multicast_probe(sfd, &idata, &hlist, PROBE_ICMP6_ECHO) != 0){
					syslog(LOG_ERR, "Error when sending multicast probe");

					if(log_stop(&idata) == -1){
						syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
					}

					exit(1);
				}

			}
			else if( hlist.mc_unrec_probe_f && ((curtime - hlist.mc_unrec_last) >= mcunrecprobeint)){
				hlist.mc_unrec_last= curtime;

				if(send_multicast_probe(sfd, &idata, &hlist, PROBE_UNREC_OPT) != 0){
					syslog(LOG_ERR, "Error when sending multicast probe");

					if(log_stop(&idata) == -1){
						syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
					}

					exit(1);
				}				
			}
			else if( (curtime - hlist.lastprocessed) > MAX_PROC_ENTRIES_INT){
				if(process_host_entries(sfd, &idata, &hlist) != 0){
					syslog(LOG_ERR, "Error while processing host entries");

					if(log_stop(&idata) == -1){
						syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
					}

					exit(1);
				}
			}
		}

		if(FD_ISSET(idata.fd, &rset)){
			error_f=0;

			do{
				if((result=pcap_next_ex(sfd, &pkthdr, &pktdata)) == -1){
					error_f=1;
					break;
				}
			}while(result==0);			

			if(error_f){
				syslog(LOG_ERR, "Error while reading packet in main loop: pcap_next_ex(): %s", pcap_geterr(sfd));

				if(log_stop(&idata) == -1){
					syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
				}

				exit(1);
			}

			pkt_ether = (struct ether_header *) pktdata;
			pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
			pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + sizeof(struct ip6_hdr));
			pkt_ns= (struct nd_neighbor_solicit *) pkt_icmp6;
			pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

			if( (pkt_end -  pktdata) < (ETHER_HDR_LEN + MIN_IPV6_HLEN))
				continue;

			if(pkt_ipv6->ip6_nxt == IPPROTO_ICMPV6){
				if(pkt_icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT){
					if( (pkt_end - (unsigned char *) pkt_ns) < sizeof(struct nd_neighbor_solicit))
						continue;

					/* 
					    If the addresses that we're using are not actually configured on the local system
					    (i.e., they are "spoofed", we must check whether it is a Neighbor Solicitation for 
					    one of our addresses, and respond with a Neighbor Advertisement. Otherwise, the kernel
					    will take care of that.
					 */
					if(is_ip6_in_address_list(&(idata.ip6_global), &(pkt_ns->nd_ns_target)) || \
						is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.ip6_local))){
							if(send_neighbor_advert(&idata, sfd, pktdata) == -1){
								syslog(LOG_ERR, "Error sending Neighbor Advertisement message");

								if(log_stop(&idata) == -1){
									syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
								}

								exit(1);
							}
					}
					else{
					/*
					   Check whether it is a Duplicate Address Detection (DAD) packet, and if so, add the ND
					   Target Address as a "candidate" address
					 */

						/* The Source Address of the DAD packets must be the Unspecified address (::) */
						if(!IN6_IS_ADDR_UNSPECIFIED(&(pkt_ipv6->ip6_src))){
							continue;
						}

						/* DAD packets are destined to multicast addresses (solicited-node) */
						if(!IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_dst))){
							continue;
						}

						/*
						   We do some sanity checks on the ND Target Address: It must not be any of the following:
						   a multicast address, the unspecified address, the loopback address, or any of our own
						   addresses
						 */
						if(IN6_IS_ADDR_MULTICAST(&(pkt_ns->nd_ns_target)) || \
						   IN6_IS_ADDR_UNSPECIFIED(&(pkt_ns->nd_ns_target)) || \
						   IN6_IS_ADDR_LOOPBACK(&(pkt_ns->nd_ns_target)) || \
						   is_ip6_in_address_list(&(idata.ip6_global), &(pkt_ns->nd_ns_target)) || \
						   is_eq_in6_addr(&(pkt_ns->nd_ns_target), &(idata.ip6_local))){
							continue;
						}

						if(hlist.ncandidates >= hlist.maxcandidates){
							syslog(LOG_INFO, "Couldn't add candidate address: Reached limit (%u)"
												" of candidate addresses", hlist.maxcandidates);
							continue;
						}

						if( (hptr=add_host_entry(&hlist, &(pkt_ns->nd_ns_target), &(pkt_ether->src))) == NULL){
							syslog(LOG_INFO, "Error while adding new host entry");
							continue;
						}

						hptr->flag= INVALID_MAPPING;
						hlist.ncandidates++;
					}
				}
				else if( (pkt_icmp6->icmp6_type == ICMP6_ECHO_REPLY) || (pkt_icmp6->icmp6_type == ICMP6_PARAM_PROB)){
					if( (pkt_end - (unsigned char *) pkt_icmp6) < sizeof(struct icmp6_hdr))
						continue;

					/*
					   Do a preliminar validation check on the ICMPv6 packet (packet size, Source Address,
					   and Destination Address).
					 */
					if(valid_icmp6_response(&idata, &hlist, pkthdr, pktdata)){
						hptr=is_ip6_in_list(&hlist, &(pkt_ipv6->ip6_src));
						curtime= time(NULL);

						if( hptr != NULL){
							hptr->nprobes= 0;
							hptr->lseen= curtime;

							if(hptr->flag != VALID_MAPPING){
								hptr->flag= VALID_MAPPING;
								hptr->fseen= curtime;

								if(hlist.ncandidates){
									(hlist.ncandidates)--;
								}
								else{
									syslog(LOG_ERR, "Candidates number is trashed!");

									if(log_stop(&idata) == -1){
										syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
									}

									exit(1);
								}

								if( log_hentry(&idata, hptr, &(hptr->fseen), ADD_ENTRY) != 0){
									syslog(LOG_ERR, "Error while logging new entry");

									if(log_stop(&idata) == -1){
										syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
									}

									exit(1);
								}
							}
						}
						else{
							if( (hptr=add_host_entry(&hlist, &(pkt_ipv6->ip6_src), &(pkt_ether->src))) == NULL){
								syslog(LOG_INFO, "Error while adding new host entry");
								continue;
							}

							if( log_hentry(&idata, hptr, &(hptr->fseen), ADD_ENTRY) != 0){
								syslog(LOG_ERR, "Error while logging new entry");

								if(log_stop(&idata) == -1){
									syslog(LOG_ERR, "Error while stopping the ipv6mon daemon");
								}

								exit(1);
							}

							if( (result=create_candidate_andress(&idata, &hlist, hptr)) == -1){
								syslog(LOG_ERR, "Error while adding candidate addresses");
								continue;
							}
							else if(result==0){
								syslog(LOG_INFO, "Could not add candidate address: Reached limit of "
											"%u candidate addresses", hlist.maxcandidates);
								continue;
							}
						}
					}
				}
				else if(pkt_icmp6->icmp6_type == ND_ROUTER_ADVERT){
					if(process_router_advert(&idata, pkthdr, pktdata) == -1){
						syslog(LOG_ERR, "Error while processing Router Advertisement"); /* XXX */
						continue;
					}
				} 
			}
		}

		if(FD_ISSET(idata.fd, &eset)){
			syslog(LOG_ERR, "Found exception on pcap_t");
			continue;
		}
	}

	exit(0);
}



/*
 * Function: usage()
 *
 * Prints the syntax of the na-attack tool
 */
void usage(void){
    puts("usage: ipv6mon [-c CONFIG_FILE] [-q] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the na-attack tool
 */
void print_help(void){
	puts( "ipv6mon version 0.2\nAn IPv6 Address Monitoring tool\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --config-file, -c    Configuration file pathname (defaults to '/etc/ipv6mon.conf')\n"
		 "  --show-config, -q    Shows configuration values and quits\n"
	     "  --help, -h           Print help for the scan6 tool\n"
	     "  --verbose, -v        Be verbose\n"
	     "\n"
	     " Programmed by Fernando Gont on behalf of CPNI (http://www.cpni.gov.uk)\n"
	     " Please send any bug reports to <fgont@si6networks.com>\n"
	);
}


/* 
 * Function: in_chksum()
 *
 * Calculate the 16-bit ICMPv6 checksum
 */

u_int16_t in_chksum(void *ptr_ipv6, void *ptr_icmpv6, size_t len){
	struct ipv6pseudohdr pseudohdr;
	struct ip6_hdr *v6packet;
	size_t nleft;
	unsigned int sum= 0;
	u_int16_t *w;
	u_int16_t answer= 0;

	v6packet=ptr_ipv6;
	
	bzero(&pseudohdr, sizeof(struct ipv6pseudohdr));
	pseudohdr.srcaddr= v6packet->ip6_src;
	pseudohdr.dstaddr= v6packet->ip6_dst;
	pseudohdr.len = htons(len);
	pseudohdr.nh = IPPROTO_ICMPV6;

	nleft=40;
	w= (u_int16_t *) &pseudohdr;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	nleft= len;
	w= (u_int16_t *) ptr_icmpv6;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1){
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}



/*
 * Function: ether_pton()
 *
 * Convert a string (printable Ethernet Address) into binary format
 */

int ether_pton(const char *ascii, struct ether_addr *etheraddr, unsigned int s){
	unsigned int i, a[6];

	if(s < ETHER_ADDR_LEN)
		return 0;
	
	if(ascii){
		if( sscanf(ascii,"%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) == 6){ 
			for(i=0;i<6;i++)
				etheraddr->a[i]= a[i];

			return 1;
		}
	}

	return 0;
}



/*
 * Function: ether_ntop()
 *
 * Convert binary Ethernet Address into printable foramt (an ASCII string)
 */

int ether_ntop(const struct ether_addr *ether, char *ascii, size_t s){
	unsigned int r;

	if(s < ETHER_ADDR_PLEN)
		return 0;

	r=snprintf(ascii, s, "%02x:%02x:%02x:%02x:%02x:%02x", ether->a[0], ether->a[1], ether->a[2], ether->a[3], \
											ether->a[4], ether->a[5]);

	if(r != 17)
		return 0;

	return 1;
}


/*
 * Function match_ipv6()
 *
 * Finds if an IPv6 address matches a prefix in a list of prefixes.
 */

unsigned int match_ipv6(struct in6_addr *prefixlist, u_int8_t *prefixlen, unsigned int nprefix, 
								struct in6_addr *ipv6addr){

	unsigned int 	i;
	struct in6_addr	dummyipv6;
    
	for(i=0; i<nprefix; i++){
		dummyipv6 = *ipv6addr;
		sanitize_ipv6_prefix(&dummyipv6, prefixlen[i]);
	
		for(j=0; j<4; j++)
			if(dummyipv6.s6_addr32[j] != prefixlist[i].s6_addr32[j])
				break;

		if(j==4)
			return 1;
	}

	return 0;
}


/*
 * match_ether()
 *
 * Finds if an Ethernet address matches any of the Ethernet addreses contained in an array.
 */

unsigned int match_ether(struct ether_addr *addrlist, unsigned int naddr, \
							    struct ether_addr *linkaddr){

	unsigned int i, j;

	for(i=0; i<naddr; i++){
		for(j=0; j<6; j++)
			if(linkaddr->a[j] != addrlist[i].a[j])
				break;

		if(j==6)
			return 1;
	}

	return 0;
}



/*
 * sanitize_ipv6_prefix()
 *
 * Clears those bits in an IPv6 address that are not within a prefix length.
 */

void sanitize_ipv6_prefix(struct in6_addr *ipv6addr, u_int8_t prefixlen){
	unsigned int	skip, i;
	u_int16_t	mask;

	skip= (prefixlen+15)/16;

	if(prefixlen%16){
		mask=0;
		for(i=0; i<(prefixlen%16); i++)
			mask= (mask>>1) | 0x8000;
	    
		ipv6addr->s6_addr16[skip-1]= ipv6addr->s6_addr16[skip-1] & htons(mask);
	}
			
	for(i=skip;i<8;i++)
		ipv6addr->s6_addr16[i]=0;
}


/*
 * randomize_ipv6_addr()
 *
 * Select a random IPv6 from a given prefix.
 */

void randomize_ipv6_addr(struct in6_addr *ipv6addr, struct in6_addr *prefix, u_int8_t preflen){
	u_int16_t mask;
	u_int8_t startrand;	
	unsigned int i;

	startrand= preflen/16;

	for(i=0; i<startrand; i++)
		ipv6addr->s6_addr16[i]= 0;

	for(i=startrand; i<8; i++)
		ipv6addr->s6_addr16[i]=random();

	if(preflen%16){
		mask=0xffff;

		for(i=0; i<(preflen%16); i++)
			mask= mask>>1;

		ipv6addr->s6_addr16[startrand]= ipv6addr->s6_addr16[startrand] & htons(mask);
	}

	for(i=0; i<=(preflen/16); i++)
		ipv6addr->s6_addr16[i]= ipv6addr->s6_addr16[i] | prefix->s6_addr16[i];

}



/*
 * randomize_ether_addr()
 *
 * Select a random Ethernet address.
 */

void randomize_ether_addr(struct ether_addr *ethaddr){
	for(i=0; i<6; i++)
		ethaddr->a[i]= random();

	ethaddr->a[0]= (ethaddr->a[0] & 0xfc) | 0x02;
}


/*
 * Function: insert_pad_opt()
 *
 * Insert a padding option (Pad1 or PadN) into an IPv6 extension header
 */

int insert_pad_opt(unsigned char *ptrhdr, const unsigned char *ptrhdrend, unsigned int padn){
	unsigned char *ptr;

	if( (ptrhdrend - ptrhdr) < padn)
		return 0;

	if(padn == 1){
		*ptrhdr= 0x00;
		return 1;
	}
	else{
		ptr=ptrhdr;
		*ptr= 0x01;
		ptr++;
		*ptr= padn-2;
		ptr+=2;
	
		while(ptr < (ptrhdr+padn)){
			*ptr= 0x00;
			ptr++;
		}    
		return 1;
	}
}



/*
 * Function: solicited_node()
 *
 * Obtains the Solicited-node multicast address corresponding to an IPv6 address.
 */

struct in6_addr solicited_node(const struct in6_addr *ipv6addr){
	struct in6_addr solicited;

	solicited.s6_addr16[0]= htons(0xff02);
	solicited.s6_addr16[1]= 0x0000;
	solicited.s6_addr16[2]= 0x0000;
	solicited.s6_addr16[3]= 0x0000;
	solicited.s6_addr16[4]= 0x0000;
	solicited.s6_addr16[5]= htons(0x0001);
	solicited.s6_addr16[6]= htons(0xff00) | ipv6addr->s6_addr16[6];
	solicited.s6_addr16[7]= ipv6addr->s6_addr16[7];

	return solicited;
}


/*
 * Function: ether_multicast()
 *
 * Obtains the Ethernet multicast address corresponding to an IPv6 multicast address.
 */

struct ether_addr ether_multicast(const struct in6_addr *ipv6addr){
	unsigned int i;
	struct ether_addr ether;

	ether.a[0]=0x33;
	ether.a[1]=0x33;

	for(i=2;i<6;i++)
		ether.a[i]= ipv6addr->s6_addr[i+10];

	return ether;
}



/*
 * Function: init_iface_data()
 *
 * Initializes the contents of "iface_data" structure
 */

int init_iface_data(struct iface_data *idata){
	bzero(idata, sizeof(struct iface_data));

	strncpy(idata->iface, iface, IFACE_LENGTH);
	idata->local_retrans = 0;
	idata->local_timeout = 1;

	idata->ip6_global.prefix= prefix_local;

	idata->ip6_global.nprefix=0;
	idata->ip6_global.maxprefix= MAX_LOCAL_ADDRESSES;
	idata->ip6_global_nconfig=0;
	idata->ip6_global_flag= INVALID_MAPPING;

	idata->prefix_ol.prefix= prefix_ols;
	idata->prefix_ol.nprefix= 0;
	idata->prefix_ol.maxprefix= MAX_PREFIXES_ONLINK;

	idata->prefix_ac.prefix= prefix_acs;
	idata->prefix_ac.nprefix= 0;
	idata->prefix_ac.maxprefix= MAX_PREFIXES_AUTO;

	idata->pending_write_f= 0;
	idata->pending_write_data= NULL;
	idata->pending_write_size= 0;

	idata->rset= &rset;
	idata->wset= &wset;
	idata->eset= &eset;
	idata->write_errors= 0;
	return 0;
}


/*
 * Function: process_router_advert()
 *
 * Process an incoming Router Advertisement message
 */

int process_router_advert(struct iface_data *idata, struct pcap_pkthdr *pkthdr, const u_char *pktdata){
	struct ip6_hdr				*pkt_ipv6;
	struct nd_router_advert 	*pkt_ra;
	unsigned char				*pkt_end;
	unsigned char				*p;
	struct nd_opt_prefix_info	*pio;
	unsigned char				 error_f=0;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
	pkt_ra = (struct nd_router_advert *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;


	/* The packet length is the minimum of what we capured, and what is specified in the
	   IPv6 Total Lenght field
	 */
	if( pkt_end > ((unsigned char *)pkt_ra + pkt_ipv6->ip6_plen) )
		pkt_end = (unsigned char *)pkt_ra + pkt_ipv6->ip6_plen;

	/*
	   Discard the packet if it is not of the minimum size to contain a Neighbor Advertisement
	   message with a source link-layer address option
	 */
	if( (pkt_end - (unsigned char *) pkt_ra) < (sizeof(struct nd_router_advert) + \
								sizeof(struct nd_opt_slla)))
		return 0;

	/*
	   Neighbor Discovery packets must have a Hop Limit of 255
	 */
	if(pkt_ipv6->ip6_hlim != 255)
		return 0;

	/*
	   Check that the IPv6 Source Address of the Router Advertisement is an IPv6 link-local
	   address.
	 */
	if( (pkt_ipv6->ip6_src.s6_addr16[0] & htons(0xffc0)) != htons(0xfe80))
		return 0;

	/* 
	   Check that that the Destination Address of the Router Advertisement is either the one
	   that we used for sending the Router Solicitation message or a multicast address 
	   (typically the all-nodes)
	 */
	if(!is_eq_in6_addr(&(pkt_ipv6->ip6_dst), &(idata->ip6_local)) && !IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_dst)))
		return 0;

	/* Check that the ICMPv6 checksum is correct. If the received checksum is valid,
	   and we compute the checksum over the received packet (including the Checkdum field)
	   the result is 0. Otherwise, the packet has been corrupted.
	*/
	if(in_chksum(pkt_ipv6, pkt_ra, pkt_end- (unsigned char *)pkt_ra) != 0)
		return 0;

	p= (unsigned char *) pkt_ra + sizeof(struct nd_router_advert);

	if( (curtime - idata->ip6_global_conftime) < RA_ACCEPT_WINDOW){
		/* Process Router Advertisement options */
		while( (p+ *(p+1) * 8) <= pkt_end && *(p+1)!=0 && !error_f){
			switch(*p){
				case ND_OPT_SOURCE_LINKADDR:
					if( (*(p+1) * 8) != sizeof(struct nd_opt_tlla))
						break;

					/* Save the link-layer address */
					idata->router_ether = *(struct ether_addr *) (p+2);
					idata->router_ip6= pkt_ipv6->ip6_src;
					break;

				case ND_OPT_PREFIX_INFORMATION:
					if(*(p+1) != 4)
						break;

					pio= (struct nd_opt_prefix_info *) p;

					if((idata->prefix_ol.nprefix) < idata->prefix_ol.maxprefix){
						if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) && \
							(pio->nd_opt_pi_prefix_len <= 128) && !is_ip6_in_prefix_list(&(pio->nd_opt_pi_prefix), \
							&(idata->prefix_ol))){

							if( (idata->prefix_ol.prefix[idata->prefix_ol.nprefix] = \
																	malloc(sizeof(struct prefix_entry))) == NULL){
								if(verbose_f)
									syslog(LOG_ERR, "process_router_advert(): Error in malloc() while "
													"learning prefixes");

								error_f=1;
								break;
							}

							(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->ip6= pio->nd_opt_pi_prefix;
							(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->len= pio->nd_opt_pi_prefix_len;
							sanitize_ipv6_prefix(&((idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->ip6), \
													(idata->prefix_ol.prefix[idata->prefix_ol.nprefix])->len);
							(idata->prefix_ol.nprefix)++;
						}
					}

					if(idata->prefix_ac.nprefix < idata->prefix_ac.maxprefix){
						if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) && \
							(pio->nd_opt_pi_prefix_len == 64) && !is_ip6_in_prefix_list(&(pio->nd_opt_pi_prefix), \
																						&(idata->prefix_ac))){

							if((idata->prefix_ac.prefix[idata->prefix_ac.nprefix] = \
																	malloc(sizeof(struct prefix_entry))) == NULL){
								if(verbose_f)
									syslog(LOG_ERR, "find_ipv6_router_full(): Error in malloc() while "
													"learning prefixes");

								error_f=1;
								break;
							}

							(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6= \
											pio->nd_opt_pi_prefix;
							(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len= \
											pio->nd_opt_pi_prefix_len;

							sanitize_ipv6_prefix(&((idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->ip6), \
													(idata->prefix_ac.prefix[idata->prefix_ac.nprefix])->len);

							if((idata->ip6_global_flag != VALID_MAPPING) && \
														idata->ip6_global.nprefix < idata->ip6_global.maxprefix){
								
								if( (idata->ip6_global.prefix[idata->ip6_global.nprefix] = \
																malloc(sizeof(struct prefix_entry))) == NULL){
									if(verbose_f)
										syslog(LOG_ERR, "find_ipv6_router_full(): Error in malloc() creating "
														"local SLAAC addresses");

									error_f=1;
									break;
								}

								generate_slaac_address(&(idata->prefix_ac.prefix[idata->prefix_ac.nprefix]->ip6), \
									&(idata->ether), &((idata->ip6_global.prefix[idata->ip6_global.nprefix])->ip6));
								(idata->ip6_global.prefix[idata->ip6_global.nprefix])->len = 64;
								(idata->ip6_global.nprefix)++;
							}
							(idata->prefix_ac.nprefix)++;
						}
					}

					break;

				default:
					break;
			}

			p= p + *(p+1) * 8;
		} /* Processing options */


		/* If we added at least one global address, we set the corresponding flag to 1 */
		if(idata->ip6_global.nprefix)
			idata->ip6_global_flag=VALID_MAPPING;
	}
	/*
	   If at least one of our addresses was added in response to an RA, we should check whether the corresponding
	   autoconf prefix is still valid for the local network
	 */
	else if((idata->ip6_global.nprefix - idata->ip6_global_nconfig) > 0){
		/* Process Router Advertisement options */
		while( (p+ *(p+1) * 8) <= pkt_end && *(p+1)!=0 && !error_f){
			switch(*p){
				case ND_OPT_PREFIX_INFORMATION:
					if(*(p+1) != 4)
						break;

					pio= (struct nd_opt_prefix_info *) p;

					if( (pio->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) && (pio->nd_opt_pi_prefix_len == 64)){

						for(i=idata->ip6_global_nconfig; i < idata->ip6_global.nprefix; i++){
							for(j=0; j < 4; j++)
								if(pio->nd_opt_pi_prefix.s6_addr16[j] != \
									(idata->ip6_global.prefix[i])->ip6.s6_addr16[j])
									break;

							if(j == 4){
								(idata->ip6_global.prefix[i])->tstamp= curtime;
								break;
							}
						}
					}

					break;

				default:
					break;
			}

			p= p + *(p+1) * 8;
		} /* Processing options */
	}

	if(error_f)
		return(-1);
	else
		return 0;	
}


/*
 * Function: is_eq_in6_addr()
 *
 * Compares two IPv6 addresses. Returns 1 if they are equal.
 */

int is_eq_in6_addr(struct in6_addr *ip1, struct in6_addr *ip2){
	unsigned int i;

	for(i=0; i<8; i++)
		if(ip1->s6_addr16[i] != ip2->s6_addr16[i])
			return 0;

	return 1;
}


/*
 * Function: ether_to_ipv6_linklocal()
 *
 * Generates an IPv6 link-local address (with modified EUI-64 identifiers) based on
 * an Ethernet address.
 */

void ether_to_ipv6_linklocal(struct ether_addr *etheraddr, struct in6_addr *ipv6addr){
	ipv6addr->s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

	for(i=1;i<4;i++)
		ipv6addr->s6_addr16[i]=0x0000;

	ipv6addr->s6_addr16[4]=  htons(((u_int16_t)(etheraddr->a[0] | 0x02) << 8) | etheraddr->a[1]);
	ipv6addr->s6_addr16[5]=  htons( ((u_int16_t)etheraddr->a[2] << 8) | 0xff);
	ipv6addr->s6_addr16[6]=  htons((u_int16_t) 0xfe00 | etheraddr->a[3]);
	ipv6addr->s6_addr16[7]=  htons(((u_int16_t)etheraddr->a[4] << 8) | etheraddr->a[5]);
}


/*
 * Function: generate_slaac_address()
 *
 * Generates an IPv6 address (with modified EUI-64 identifiers) based on
 * a IPv6 prefix and an Ethernet address.
 */

void generate_slaac_address(struct in6_addr *prefix, struct ether_addr *etheraddr, struct in6_addr *ipv6addr){
	ipv6addr->s6_addr16[0]= htons(0xfe80); /* Link-local unicast prefix */

	for(i=0;i<4;i++)
		ipv6addr->s6_addr16[i]= prefix->s6_addr16[i];

	ipv6addr->s6_addr16[4]=  htons(((u_int16_t) (etheraddr->a[0] | 0x02) << 8) | etheraddr->a[1]);
	ipv6addr->s6_addr16[5]=  htons( ((u_int16_t)etheraddr->a[2] << 8) | 0xff);
	ipv6addr->s6_addr16[6]=  htons((u_int16_t) 0xfe00 | etheraddr->a[3]);
	ipv6addr->s6_addr16[7]=  htons(((u_int16_t)etheraddr->a[4] << 8) | etheraddr->a[5]);
}


/*
 * match_ipv6_to_prefixes()
 *
 * Finds out whether an IPv6 address matches any IPv6 prefix in an array
 */

int match_ipv6_to_prefixes(struct in6_addr *ipv6addr, struct in6_addr *prefixes, unsigned char *preflen, \
				unsigned int nprefixes){
	unsigned int	i, j, full16, rbits;
	u_int16_t	mask;

	for(i=0; i<nprefixes; i++){
		full16= preflen[i]/16;
		for(j=0; j<full16; j++){
			if(ipv6addr->s6_addr16[j] != prefixes[i].s6_addr16[j])
				break;
		}

		if(j == full16){
			if((rbits= preflen[i]%16) == 0)
				return 1;
			else{
				mask= 0xffff;
				mask= mask<<rbits;
				if(prefixes[i].s6_addr16[full16] == (ipv6addr->s6_addr16[full16] & htons(mask)))
					return 1;
			}
		}
	}

	return 0;
}



/*
 * Function: free_host_entries()
 *
 * Releases memory allocated for holding IPv6 addresses and Ethernet addresses
 */

void free_host_entries(struct host_list *hlist){
	unsigned int i;

	for(i=0; i< hlist->nhosts; i++)
		free(hlist->host[i]);

	hlist->nhosts=0;	/* Set the number of entries to 0, to reflect the released memory */
	return;
}


/*
 * Function: create_candidate_address()
 *
 * Generates list of cadidate addresses based on a host_entry structure
 */

int create_candidate_andress(struct iface_data *idata, struct host_list *hlist, struct host_entry *hentry){
	unsigned int	i, j;
	struct in6_addr	caddr;
	struct host_entry *hptr;


	/* 
	   We create one candidate address with the Interface-ID of the IPv6 address,
	   for each of our autoconf prefixes
	 */
	for(i=0; (i < idata->prefix_ac.nprefix) && (hlist->nhosts < hlist->maxhosts); i++){

		if(hlist->ncandidates >= hlist->maxcandidates){
			syslog(LOG_INFO, "Couldn't add candidate address: Reached limit (%u)"
								" of candidate addresses", hlist->maxcandidates);
			return 0;
		}

		for(j=0; j<4; j++)
			caddr.s6_addr16[j] = (idata->prefix_ac.prefix[i])->ip6.s6_addr16[j];

		for(j=4; j<8; j++)
			caddr.s6_addr16[j] = hentry->ip6.s6_addr16[j];

		/* We discard the candidate address if it is already present in our list */
		if(is_ip6_in_list(hlist, &caddr) != NULL)
			continue;

		if( (hptr= add_host_entry(hlist, &caddr, &(hentry->ether))) == NULL){
			return(-1);
		}

		hptr->flag= INVALID_MAPPING;
		(hlist->ncandidates)++;
	}

	/*
	   If the newly-added address is not a link-local address, we create a candidate address with the
	   link-local prefix (fe80::/64) and the Interface-ID of the newly-added address.
	 */
	if( (hlist->nhosts < hlist->maxhosts) && (hentry->ip6.s6_addr16[0] != htons(0xfe80))){

		if(hlist->ncandidates >= hlist->maxcandidates){
			syslog(LOG_INFO, "Couldn't add candidate address: Reached limit (%u)"
								" of candidate addresses", hlist->maxcandidates);
			return 0;
		}

		for(j=0; j<4; j++)
			caddr.s6_addr16[j] = idata->ip6_local.s6_addr16[j];

		for(j=4; j<8; j++)
			caddr.s6_addr16[j] = hentry->ip6.s6_addr16[j];

		/* We discard the candidate address if it is already present in our list */
		if(is_ip6_in_list(hlist, &caddr) != NULL)
			return 0;

		if( (hptr= add_host_entry(hlist, &caddr, &(hentry->ether))) == NULL){
			if(verbose_f)
				syslog(LOG_ERR, "create_candidate_andress(): Failed to add candidate entry");

			return(-1);
		}

		hptr->flag= INVALID_MAPPING;
		(hlist->ncandidates)++;
	}

	return 0;
}



/*
 * Function: src_addr_sel()
 *
 * Selects a Source Address for a given Destination Address
 */

struct in6_addr *src_addr_sel(struct iface_data *idata, struct in6_addr *dst){
	u_int16_t	mask16;
	unsigned int	i, j, full16, rest16;
	/*
	   If the destination address is a link-local address, we select our link-local
	   address as the Source Address. If the dst address is a global unicast address
	   we select our first matching address, or else our first global address.
	   Worst case scenario, we don't have global address and must use our link-local
	   address.
	*/   

	if( (dst->s6_addr16[0] & htons(0xffc0)) == htons(0xfe80)){
		return( &(idata->ip6_local));
	}
	else if(idata->ip6_global_flag == VALID_MAPPING){
		for(i=0; i < idata->ip6_global.nprefix; i++){
				full16=(idata->ip6_global.prefix[i])->len / 16;
				rest16=(idata->ip6_global.prefix[i])->len % 16;
				mask16 = 0xffff;

				for(j=0; j < full16; j++)
					if( dst->s6_addr16[j] != (idata->ip6_global.prefix[i])->ip6.s6_addr16[j])
						break;

				if( (j == full16) && rest16){
					mask16 = mask16 << (16 - rest16);

					if( (dst->s6_addr16[full16] & mask16) == ((idata->ip6_global.prefix[i])->ip6.s6_addr16[full16] \
																									& mask16))
						return( &((idata->ip6_global.prefix[i])->ip6));
				}
		}

		return( &((idata->ip6_global.prefix[0])->ip6));
	}
	else{
		return( &(idata->ip6_local));
	}
}


/*
 * Function: is_ip6_in_list()
 *
 * Checks whether an IPv6 address is present in a host list.
 */

struct host_entry *is_ip6_in_list(struct host_list *hlist, struct in6_addr *target){
	u_int16_t			ckey;
	struct host_entry	*chentry;

	ckey= key(hlist, target);

	for(chentry= hlist->host[ckey]; chentry != NULL; chentry=chentry->next)
		if( is_eq_in6_addr(target, &(chentry->ip6)) )
			return chentry;

	return NULL; 
}


/*
 * Function: is_ip6_in_prefix_list()
 *
 * Checks whether an IPv6 address is present in a prefix list.
 */

int is_ip6_in_prefix_list(struct in6_addr *target, struct prefix_list *plist){
	unsigned int i, j, full16, rest16;
	u_int16_t	mask16;

	for(i=0; i < plist->nprefix; i++){
		full16=(plist->prefix[i])->len / 16;
		rest16=(plist->prefix[i])->len % 16;
		mask16 = 0xffff;

		for(j=0; j < full16; j++)
			if(target->s6_addr16[j] != (plist->prefix[i])->ip6.s6_addr16[j])
				break;

		if( (j == full16) && rest16){
			mask16 = mask16 << (16 - rest16);

			if( (target->s6_addr16[full16] & mask16) == ((plist->prefix[i])->ip6.s6_addr16[full16] & mask16))
				return 1;
		}
	}

	return 0;
}

/*
 * Function: is_ip6_in_address_list()
 *
 * Checks whether an IPv6 address is present in an address list.
 */

int is_ip6_in_address_list(struct prefix_list *plist, struct in6_addr *target){
	unsigned int i, j;

	for(i=0; i < plist->nprefix; i++){
		for(j=0; j < 8; j++){
			if(target->s6_addr16[j] != (plist->prefix[i])->ip6.s6_addr16[j])
				break;
		}

		if(j == 8)
			return 1;
	}

	return 0;
}


/*
 * Function: lookup_ip6_in_address_list()
 *
 * Checks whether an IPv6 address is present in an address list, and returns a pointer to the corresponding entry.
 */

struct prefix_entry *lookup_ip6_in_address_list(struct prefix_list *plist, struct in6_addr *target){
	unsigned int i, j;

	for(i=0; i < plist->nprefix; i++){
		for(j=0; j < 8; j++){
			if(target->s6_addr16[j] != (plist->prefix[i])->ip6.s6_addr16[j])
				break;
		}

		if(j == 8)
			return(plist->prefix[i]);
	}

	return NULL;
}


/*
 * Function: send_neighbor_advertisement()
 *
 * Send a Neighbor advertisement in response to a Neighbor Solicitation message
 */

int send_neighbor_advert(struct iface_data *idata, pcap_t *pfd,  const u_char *pktdata){
	struct ether_header			*pkt_ether;
	struct ip6_hdr				*pkt_ipv6;
	struct nd_neighbor_solicit	*pkt_ns;
	unsigned char				*ptr;
	unsigned char 				*v6buffer;
	struct ether_header			*ethernet;
	struct ip6_hdr				*ipv6;
	struct nd_neighbor_advert	*na;
	struct	nd_opt_tlla			*tllaopt;


	ethernet= (struct ether_header *) wbuffer;
	v6buffer = (unsigned char *) ethernet + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;
	na= (struct nd_neighbor_advert *) ((char *) v6buffer + MIN_IPV6_HLEN);
	ptr = (unsigned char *) na;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
	pkt_ns = (struct nd_neighbor_solicit *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);

	ethernet->ether_type = htons(0x86dd);
	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_nxt= IPPROTO_ICMPV6;

	if( (ptr+sizeof(struct nd_neighbor_advert)) > (v6buffer+idata->mtu)){
		if(verbose_f)
			syslog(LOG_ERR, "send_neighbor_advert(): Packet too large while constructing "
							"Neighbor Advertisement message");

		return(-1);
	}

	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	ptr += sizeof(struct nd_neighbor_advert);

	if( (ptr+sizeof(struct nd_opt_tlla)) <= (v6buffer+idata->mtu) ){
		tllaopt = (struct nd_opt_tlla *) ptr;
		tllaopt->type= ND_OPT_TARGET_LINKADDR;
		tllaopt->length= TLLA_OPT_LEN;
		bcopy(idata->ether.a, tllaopt->address, ETH_ALEN);
		ptr += sizeof(struct nd_opt_tlla);
	}
	else{
		if(verbose_f)
			syslog(LOG_ERR, "send_neighbor_advert(): Packet Too Large while inserting TLLA option in NA message");

		return(-1);
	}

	/* If the IPv6 Source Address of the incoming Neighbor Solicitation is the unspecified 
	   address (::), the Neighbor Advertisement must be directed to the IPv6 all-nodes 
	   multicast address (and the Ethernet Destination address should be 33:33:33:00:00:01). 
	   Otherwise, the Neighbor Advertisement is sent to the IPv6 Source Address (and 
	   Ethernet Source Address) of the incoming Neighbor Solicitation message
	 */
	pkt_ipv6addr = &(pkt_ipv6->ip6_src);

	if(IN6_IS_ADDR_UNSPECIFIED(pkt_ipv6addr)){
		na->nd_na_flags_reserved = 0;

		if ( inet_pton(AF_INET6, ALL_NODES_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
			if(verbose_f)
				syslog(LOG_ERR, "send_neighbor_advert(): Error converting all-nodes multicast address");

			return(-1);
		}

		if(ether_pton(ETHER_ALLNODES_LINK_ADDR, &(ethernet->dst), ETHER_ADDR_LEN) == 0){
			if(verbose_f)
				syslog(LOG_ERR, "send_neighbor_advert(): Error converting all-nodes link-local address");

			return(-1);
		}
	}
	else{
		ipv6->ip6_dst = pkt_ipv6->ip6_src;
		ethernet->dst = pkt_ether->src;

		/* 
		   Set the "Solicited" flag if NS was sent from an address other than the unspecified
		   address (i.e., the response will be unicast). 
		 */ 

		na->nd_na_flags_reserved =  ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_SOLICITED;
	}

	ethernet->src = idata->ether;

	/* 
	   If the Neighbor Solicitation message was directed to one of our unicast addresses, the IPv6 Source
	   Address is set to that address. Otherwise, we set the IPv6 Source Address to our link-local address.
	 */

	pkt_ipv6addr = &(pkt_ipv6->ip6_dst);

	if(IN6_IS_ADDR_MULTICAST(pkt_ipv6addr)){
		ipv6->ip6_src = idata->ip6_local;
	}
	else{
		if(is_eq_in6_addr(pkt_ipv6addr, &(idata->ip6_local))){
			ipv6->ip6_src = idata->ip6_local;	
		}
		else if(idata->ip6_global_flag == VALID_MAPPING){
			for(i=0; i < idata->ip6_global.nprefix; i++){
				if(is_eq_in6_addr(pkt_ipv6addr, &((idata->ip6_global.prefix[i])->ip6))){
					ipv6->ip6_src = (idata->ip6_global.prefix[i])->ip6;	
					break;
				}
			}

			if(i == idata->ip6_global.nprefix)
				return 0;
		}
		else{
			return 0;
 		}
	}

	na->nd_na_target= pkt_ns->nd_ns_target;

	na->nd_na_cksum = 0;
	na->nd_na_cksum = in_chksum(v6buffer, na, ptr-((unsigned char *)na));


	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);

	if(FD_ISSET(idata->fd, idata->wset)){
		if((nw=pcap_inject(pfd, wbuffer, ptr - wbuffer)) == -1){
			if(verbose_f)
				syslog(LOG_ERR, "send_neighbor_advert(): pcap_inject(): %s", pcap_geterr(pfd));

			return(-1);
		}

		if(nw != (ptr-wbuffer)){
			if(verbose_f)
				syslog(LOG_ERR, "send_neighbor_advert(): pcap_inject(): only wrote %lu bytes "
								"(rather than %lu bytes)", (LUI) nw, (LUI) (ptr-wbuffer));

			idata->pending_write_f= 1;
			idata->pending_write_data= wbuffer;
			idata->pending_write_size= ptr- wbuffer;
			(idata->write_errors)++;
			return(0);
		}
	}
	else{
		idata->pending_write_f= 1;
		idata->pending_write_data= wbuffer;
		idata->pending_write_size= ptr- wbuffer;
	}

	return 0;
}



/*
 * Function: send_router_solicit()
 *
 * Send a Router Solicitation message
 */

int send_router_solicit(pcap_t *pfd, struct iface_data *idata){
	unsigned char				*ptr;
	unsigned int 				rs_max_packet_size;
	struct ether_header 		*ether;
	unsigned char 				*v6buffer;
	struct ip6_hdr 				*ipv6;
	struct nd_router_solicit	*rs;
	struct nd_opt_slla 			*sllaopt;

	rs_max_packet_size = idata->mtu;
	ether = (struct ether_header *) wbuffer;
	v6buffer = (unsigned char *) ether + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_src= idata->ip6_local;

	if ( inet_pton(AF_INET6, ALL_ROUTERS_MULTICAST_ADDR, &(ipv6->ip6_dst)) <= 0){
		if(verbose_f)
			syslog(LOG_ERR, "find_ipv6_router_full(): Error converting All Routers "
							"address from presentation to network format");

		return(-1);
	}

	ether->src = idata->ether;

	if(ether_pton(ETHER_ALLROUTERS_LINK_ADDR, &(ether->dst), sizeof(struct ether_addr)) == 0){
		if(verbose_f)
			syslog(LOG_ERR, "find_ipv6_router_full(): ether_pton(): Error converting all-nodes multicast address");

		return(-1);
	}

	ether->ether_type = htons(0x86dd);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);
	*prev_nh = IPPROTO_ICMPV6;

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	if( (ptr+sizeof(struct nd_router_solicit)) > (v6buffer+rs_max_packet_size)){
		if(verbose_f)
			syslog(LOG_ERR, "find_ipv6_router_full(): Packet too large while inserting Router Solicitation header");

		return(-1);
	}

	rs= (struct nd_router_solicit *) (ptr);

	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	rs->nd_rs_code = 0;
	rs->nd_rs_reserved = 0;

	ptr += sizeof(struct nd_router_solicit);
	sllaopt = (struct nd_opt_slla *) ptr;    

	if( (ptr+sizeof(struct nd_opt_slla)) > (v6buffer+rs_max_packet_size)){
		if(verbose_f)
			syslog(LOG_ERR, "find_ipv6_router_full(): RS message too large while processing source "
							"link-layer addresss opt.");

		return(-1);
	}

	sllaopt->type= ND_OPT_SOURCE_LINKADDR;
	sllaopt->length= SLLA_OPT_LEN;
	bcopy( &(idata->ether.a), sllaopt->address, ETH_ALEN);
	ptr += sizeof(struct nd_opt_slla);

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	rs->nd_rs_cksum = 0;
	rs->nd_rs_cksum = in_chksum(v6buffer, rs, ptr-((unsigned char *)rs));

	if(FD_ISSET(idata->fd, idata->wset)){
		if((nw=pcap_inject(pfd, wbuffer, ptr - wbuffer)) == -1){
			if(verbose_f)
				syslog(LOG_ERR, "send_router_solicit(): pcap_inject(): %s", pcap_geterr(pfd));

			idata->pending_write_f= 1;
			idata->pending_write_data= wbuffer;
			idata->pending_write_size= ptr- wbuffer;
			(idata->write_errors)++;
			return(0);
		}

		if(nw != (ptr-wbuffer)){
			if(verbose_f)
				syslog(LOG_ERR, "send_router_solicit(): pcap_inject(): only wrote %lu bytes "
								"(rather than %lu bytes)", (LUI) nw, (LUI) (ptr-wbuffer));

			idata->pending_write_f= 1;
			idata->pending_write_data= wbuffer;
			idata->pending_write_size= ptr- wbuffer;
			(idata->write_errors)++;
			return(0);
		}
	}
	else{
		idata->pending_write_f= 1;
		idata->pending_write_data= wbuffer;
		idata->pending_write_size= ptr- wbuffer;
	}

	return 0;
}




/*
 * Function: valid_icmp6_response()
 *
 * Checks whether the response to an ICMPv6 probe is valid
 */

int valid_icmp6_response(struct iface_data *idata, struct host_list *hlist, struct pcap_pkthdr *pkthdr,\
			const u_char *pktdata){

	struct ether_header	*pkt_ether;
	struct ip6_hdr		*pkt_ipv6;
	struct icmp6_hdr	*pkt_icmp6, *pkt_icmp6_icmp6;
	unsigned char		*pkt_end;

	pkt_ether = (struct ether_header *) pktdata;
	pkt_ipv6 = (struct ip6_hdr *)((char *) pkt_ether + ETHER_HDR_LEN);
	pkt_icmp6 = (struct icmp6_hdr *) ((char *) pkt_ipv6 + MIN_IPV6_HLEN);
	pkt_icmp6_icmp6= (struct icmp6_hdr *) ((unsigned char *) pkt_icmp6 + sizeof(struct icmp6_hdr) +\
						sizeof(struct ip6_hdr) + MIN_DST_OPT_HLEN);
	pkt_end = (unsigned char *) pktdata + pkthdr->caplen;

	switch(pkt_icmp6->icmp6_type){
		case ICMP6_ECHO_REPLY:
			/* The packet length is the minimum of what we capured, and what is specified in the
			   IPv6 Total Lenght field
			 */
			if( pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen) )
				pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			if( (pkt_end - (unsigned char *) pkt_icmp6) < (sizeof(struct icmp6_hdr) + \
									ICMPV6_ECHO_PAYLOAD_SIZE) ){
				return 0;
			}

			if(pkt_icmp6->icmp6_data16[0] != htons(getpid())){
				return 0;
			}

			break;

		case ICMP6_PARAM_PROB:
			/* The packet length is the minimum of what we capured, and what is specified in the
			   IPv6 Total Lenght field
			 */
			if( pkt_end > ((unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen) )
				pkt_end = (unsigned char *)pkt_icmp6 + pkt_ipv6->ip6_plen;

			/*
			   Discard the packet if it is not of the minimum size to contain an ICMPv6 
			   header and the payload we included in the ICMPv6 Echo Request
			 */
			if( (pkt_end - (unsigned char *) pkt_icmp6) < (sizeof(struct icmp6_hdr) + \
						+ sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
						  ICMPV6_ECHO_PAYLOAD_SIZE) ){
				return 0;
			}

			if( pkt_icmp6->icmp6_code != ICMP6_PARAMPROB_OPTION){
				return 0;
			}

			if(pkt_icmp6_icmp6->icmp6_data16[0] != htons(getpid())){
				return 0;
			}

			break;

		default:
			return 0;
			break;
	}

	/*
	   Check that the Source Address of the Packet is "valid"
	 */
	if(IN6_IS_ADDR_UNSPECIFIED(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	if(IN6_IS_ADDR_LOOPBACK(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	if(IN6_IS_ADDR_MULTICAST(&(pkt_ipv6->ip6_src))){
		return 0;
	}

	/* 
	   Check that that the Destination Address of the incoming packet is one
	   of our addresses.
	 */
	if(!is_eq_in6_addr(&(idata->ip6_local), &(pkt_ipv6->ip6_dst)) && \
					!is_ip6_in_address_list(&(idata->ip6_global), &(pkt_ipv6->ip6_dst))){
		return 0;
	}

	/* Check that the ICMPv6 checksum is correct */
	if(in_chksum(pkt_ipv6, pkt_icmp6, pkt_end-((unsigned char *)pkt_icmp6)) != 0){
		return 0;
	}

	return 1;
}


/*
 * Function: get_if_addrs()
 *
 * Obtains Ethernet and IPv6 addresses of a network interface card
 */

int get_if_addrs(struct iface_data *idata){
	struct ifaddrs	*ifptr, *ptr;
	struct sockaddr_in6	*sockin6ptr;

#ifdef __linux__
	struct sockaddr_ll	*sockpptr;
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	struct sockaddr_dl	*sockpptr;
#endif

	if(getifaddrs(&ifptr) != 0){
		if(verbose_f){
			syslog(LOG_ERR, "get_if_addrs(): Error while learning addresses of the %s interface", idata->iface);
		}

		return(-1);
	}

	for(ptr=ifptr; ptr != NULL; ptr= ptr->ifa_next){
		if(ptr->ifa_addr != NULL){
#ifdef __linux__
			if( !(idata->ether_flag) && ((ptr->ifa_addr)->sa_family == AF_PACKET)){
				if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
					sockpptr = (struct sockaddr_ll *) (ptr->ifa_addr);
					if(sockpptr->sll_halen == 6){
						idata->ether = *((struct ether_addr *)sockpptr->sll_addr);
						idata->ether_flag=1;
					}
				}
			}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
			if( !(idata->ether_flag) && ((ptr->ifa_addr)->sa_family == AF_LINK)){
				if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
					sockpptr = (struct sockaddr_dl *) (ptr->ifa_addr);
					if(sockpptr->sdl_alen == 6){
						idata->ether= *((struct ether_addr *)(sockpptr->sdl_data + sockpptr->sdl_nlen));
						idata->ether_flag= 1;
					}
				}
			}
#endif
			else if((ptr->ifa_addr)->sa_family == AF_INET6){
				sockin6ptr= (struct sockaddr_in6 *) (ptr->ifa_addr);

				if(!(idata->ip6_local_flag) && (((sockin6ptr->sin6_addr).s6_addr16[0] & htons(0xffc0)) == htons(0xfe80))){
					if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
						idata->ip6_local = sockin6ptr->sin6_addr;
#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
						/* BSDs store the interface index in s6_addr16[1], so we must clear it */
						idata->ip6_local.s6_addr16[1] =0;
						idata->ip6_local.s6_addr16[2] =0;
						idata->ip6_local.s6_addr16[3] =0;					
#endif
						idata->ip6_local_flag= 1;
					}
				}
				else if((((sockin6ptr->sin6_addr).s6_addr16[0] & htons(0xffc0)) != htons(0xfe80))){
					if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
						if(!is_ip6_in_prefix_list( &(sockin6ptr->sin6_addr), &(idata->ip6_global))){
							if(idata->ip6_global.nprefix < idata->ip6_global.maxprefix){
								if( (idata->ip6_global.prefix[idata->ip6_global.nprefix] = \
													malloc(sizeof(struct prefix_entry))) == NULL){
									if(verbose_f)
										syslog(LOG_ERR, "get_if_addrs(): Error while storing Source Address");

									return(-1);
								}

								(idata->ip6_global.prefix[idata->ip6_global.nprefix])->len = 64;
								(idata->ip6_global.prefix[idata->ip6_global.nprefix])->ip6 = sockin6ptr->sin6_addr;
								idata->ip6_global.nprefix++;
								idata->ip6_global_nconfig++;
								idata->ip6_global_flag= VALID_MAPPING;
							}
						}
					}
				}
			}
		}
	}

	freeifaddrs(ifptr);
	return(0);
}


/*
 * Function: check_local_addresses()
 *
 * Check whether our local addresses are still valid, and if not, remove them
 */

int check_local_addresses(struct iface_data *idata){
	struct ifaddrs	*ifptr, *ptr;
	struct sockaddr_in6	*sockin6ptr;
	struct prefix_entry *prefptr;
	time_t	curtime;
	unsigned int i;

	curtime= time(NULL);

	/* If at least one of our addresses was a locally-configured address, check whether they are still valid */
	if(idata->ip6_global_nconfig){
		if(getifaddrs(&ifptr) != 0){
			if(verbose_f){
				syslog(LOG_ERR, "get_if_addrs(): Error while learning addresses of the %s interface", idata->iface);
			}

			return(-1);
		}

		for(ptr=ifptr; ptr != NULL; ptr= ptr->ifa_next){
			if(ptr->ifa_addr != NULL){
				if((ptr->ifa_addr)->sa_family == AF_INET6){
					sockin6ptr= (struct sockaddr_in6 *) (ptr->ifa_addr);

					if((((sockin6ptr->sin6_addr).s6_addr16[0] & htons(0xffc0)) != htons(0xfe80))){
						if(strncmp(idata->iface, ptr->ifa_name, IFACE_LENGTH-1) == 0){
							if( (prefptr=lookup_ip6_in_address_list(&(idata->ip6_global), &(sockin6ptr->sin6_addr))) != NULL){
								prefptr->tstamp=curtime;
							}
						}
					}
				}
			}
		}

		freeifaddrs(ifptr);

	}

	/*
	   Addresses configured as a result of Router Advertisements should already have their timestamp updated
	   (when an if a corresponding RA was received while probing
	 */


	for(i=0; i<idata->ip6_global.nprefix; i++)
		if(( curtime - (idata->ip6_global.prefix[i])->tstamp) >= LOCAL_ADDRESS_TIMEOUT)
			break;

	if(i < idata->ip6_global.nprefix){
		idata->ip6_global_flag=INVALID_MAPPING;
		idata->ip6_global_conftime=curtime;
		idata->last_rs=0;

		/* Remove all of our global addresses */
		for(i=0; i < idata->ip6_global.nprefix; i++)
			free(idata->ip6_global.prefix[i]);

		idata->ip6_global.nprefix=0;
		idata->ip6_global_nconfig=0;

		/* Remove all autoconf prefixes (used for candidate addresses) */
		for(i=0; i < idata->prefix_ac.nprefix; i++)
			free(idata->prefix_ac.prefix[i]);

		idata->prefix_ac.nprefix=0;

		/* Remove all "on-link" prefixes (currently unused) */
		for(i=0; i < idata->prefix_ol.nprefix; i++)
			free(idata->prefix_ol.prefix[i]);

		idata->prefix_ol.nprefix=0;
		return 0;
	}
	else{
		idata->ip6_global_lastcheck= curtime;
		return 1;
	}
}


/*
 * Function: init_host_list()
 *
 * Initilizes a host_list structure
 */

int init_host_list(struct host_list *hlist){
	time_t curtime;

	curtime= time(NULL);

	bzero(hlist, sizeof(struct host_list));

	if( (hlist->host = malloc(MAX_LIST_ENTRIES * sizeof(struct host_entry *))) == NULL){
		if(verbose_f){
			syslog(LOG_ERR, "init_host_list(): Not enough memory while initializing host list");
		}

		return(-1);
	}

	for(i=0; i < MAX_LIST_ENTRIES; i++)
		hlist->host[i]= NULL;

	hlist->nhosts= 0;
	hlist->maxhosts= maxaddrentries;
	hlist->ncandidates= 0;
	hlist->maxcandidates= maxcandentries;
	hlist->lastprocessed= curtime;
	hlist->lastgcollection= curtime;

	hlist->key_l= rand();
	hlist->key_h= rand();

	hlist->mc_unrec_probe_f=1;
	hlist->mc_unrec_state= SCAN_LOCAL;
	hlist->mc_unrec_naddr= 0;
	hlist->mc_unrec_seq= rand();
	hlist->mc_unrec_last= 0;

	hlist->mc_echo_probe_f=1;
	hlist->mc_echo_state= SCAN_LOCAL;
	hlist->mc_echo_naddr= 0;
	hlist->mc_echo_seq= rand();
	hlist->mc_echo_last= curtime - mcechoprobeint / 2;

	hlist->np_key= 0;
	hlist->np_hentry= NULL;

	return(0);
}


/*
 * Function: key()
 *
 * Compute a key for accessing the hash-table of a host_list structure
 */

u_int16_t key(struct host_list *hlist, struct in6_addr *ipv6){
		return( ((hlist->key_l ^ ipv6->s6_addr16[0] ^ ipv6->s6_addr16[7]) \
				^ (hlist->key_h ^ ipv6->s6_addr16[1] ^ ipv6->s6_addr16[6])) % MAX_LIST_ENTRIES);
}


/*
 * Function: add_host_entry()
 *
 * Add a host_entry structure to the hash table
 */

struct host_entry *add_host_entry(struct host_list *hlist, struct in6_addr *ipv6, struct ether_addr *ether){
	struct host_entry	*hentry, *ptr;
	u_int16_t			hkey;

	hkey= key(hlist, ipv6);

	if(hlist->nhosts >= hlist->maxhosts){
		if(verbose_f){
			syslog(LOG_INFO, "add_host_entry(): Reached maximum number of hosts");
		}

		return(NULL);
	}

	if( (hentry= malloc(sizeof(struct host_entry))) == NULL){
		if(verbose_f){
			syslog(LOG_ERR, "add_host_entry(): Not enough memory while adding host entry");
		}

		return(NULL);
	}

	bzero(hentry, sizeof(struct host_entry));
	hentry->ip6 = *ipv6;
	hentry->ether= *ether;
	hentry->flag= VALID_MAPPING;
	hentry->fseen= time(NULL);
	hentry->lseen= time(NULL);
	hentry->lprobed= 0;
	hentry->nprobes= 0;
	hentry->next= NULL;
	hentry->ffactor= rand()%MAX_FUDGE_FACTOR;

	if(hlist->host[hkey] == NULL){
		/* First node in chain */
		hlist->host[hkey]= hentry;
		hentry->prev= NULL;
	}
	else{
		/* Find last node in list */
		for(ptr=hlist->host[hkey]; ptr->next != NULL; ptr= ptr->next);

		hentry->prev= ptr;
		ptr->next= hentry;
	}

	(hlist->nhosts)++;

	return(hentry);
}


/*
 * Function: del_host_entry()
 *
 * Remove a host_entry structure from the hash table
 */

int del_host_entry(struct host_list *hlist, struct host_entry *hentry){
	u_int16_t hkey;

	hkey= key(hlist, &(hentry->ip6));

	/* If this was not the last node in the list, make our next node point to our previous node */
	if(hentry->next != NULL){
		(hentry->next)->prev = hentry->prev;
	}

	/* If this is not the first node in the list, the previous node should point to our next node */
	if(hentry->prev != NULL){
		(hentry->prev)->next= hentry->next;
	}
	else{
		hlist->host[hkey]= hentry->next;
	}

	/* If this was the next host_entry to process, the next node should be come the next entry to process */
	if(hlist->np_key == hkey && hlist->np_hentry == hentry){
		hlist->np_hentry= hentry->next;
	}

	if(hentry->flag != VALID_MAPPING){
		if(hlist->ncandidates){
			(hlist->ncandidates)--;
		}
		else{
			if(verbose_f){
				syslog(LOG_ERR, "del_host_entry(): Host list is trashed!");
				return(-1);
			}
		}
	}

	if(hlist->nhosts){
		(hlist->nhosts)--;
	}
	else{
		if(verbose_f){
			syslog(LOG_ERR, "del_host_entry(): Host list is trashed!");
			return(-1);
		}
	}

	free(hentry);
	return(0);
}


/*
 * Function: process_host_entries()
 *
 * Compute a key for accessing the hash-table of a host_list structure
 */

int process_host_entries(pcap_t *pfd, struct iface_data *idata, struct host_list *hlist){
	unsigned int		nkeys=0, nhosts=0;
	struct host_entry	*chentry, *saved_hentry;
	time_t				curtime;

	if(hlist->nhosts == 0)
		return 0;

	curtime = time(NULL);
	chentry= hlist->np_hentry;

	while(nkeys < MAX_LIST_ENTRIES && nhosts < hlist->nhosts){
		nkeys++;

		while(chentry != NULL){
			nhosts++;

			/* Check whether host should be eliminated from list */
			if( ((chentry->flag == VALID_MAPPING) && ((curtime - chentry->lseen) >= addrtimeout)) ||\
				((chentry->flag == INVALID_MAPPING) && ((curtime - chentry->lseen) >= candaddrtimeout))){

				/*
				   We must save chentry->next, because it may be impossible to access if we
				   del_host_entry() the current node
				 */
				saved_hentry= chentry->next;

				if( (chentry->flag == VALID_MAPPING) && log_hentry(idata, chentry, &curtime, DEL_ENTRY) != 0){
					if(verbose_f)
						syslog(LOG_ERR, "process_host_entries(): Error while logging new entry");

					return(-1);
				}

				if(del_host_entry(hlist, chentry) != 0){
					if(verbose_f)
						syslog(LOG_ERR, "process_host_entries(): Error while eliminating host entry");

					return(-1);
				}
				else{
					chentry= saved_hentry;
				}
			}
				
			/* Check whether the host should be probed */
			else if( (chentry->flag != VALID_MAPPING) || ((curtime - chentry->lseen) >= maxunprobedint)){
				if( (curtime - chentry->lprobed) >= (unicastprobeint + chentry->ffactor)){
					if(send_host_probe(pfd, idata, ((chentry->nprobes % 2)?PROBE_ICMP6_ECHO:PROBE_UNREC_OPT), chentry)\
																										 == -1){
						if(verbose_f)
							syslog(LOG_ERR, "process_host_entries(): Error while sending probe to host");

						return(-1);
					}
					else{
						chentry->lprobed= curtime;
						(chentry->nprobes)++;
						hlist->np_hentry= chentry->next;
						return(0);
					}
				}
				else{
					chentry= chentry->next;
				}
			}
		}

		(hlist->np_key)++;

		if(hlist->np_key >= MAX_LIST_ENTRIES || nhosts == hlist->nhosts){
			hlist->np_key= 0;
			hlist->lastprocessed= curtime;
		}

		hlist->np_hentry = hlist->host[hlist->np_key];
	}

	return 0;
}


/*
 * Function: gcollection_host_entries()
 *
 * Remove old entries from host_list
 */

int gcollection_host_entries(struct iface_data *idata, struct host_list *hlist){
	unsigned int		nkeys=0, nhosts;
	time_t				curtime;
	struct host_entry	*chentry;

	if(hlist->nhosts == 0)
		return 0;

	for(nkeys=0; (nkeys <= MAX_LIST_ENTRIES) && (nhosts < hlist->nhosts); nkeys++){

		for(chentry= hlist->host[nkeys]; chentry != NULL; chentry= chentry->next){
			nhosts++;
			curtime = time(NULL);

			/* Check whether host should be eliminated from list */
			if( ((chentry->flag == VALID_MAPPING) && ((curtime - chentry->lseen) >= addrtimeout)) ||\
					((chentry->flag == INVALID_MAPPING) && ((curtime - chentry->lseen) >= candaddrtimeout))){

				if( (chentry->flag == VALID_MAPPING) && log_hentry(idata, chentry, &curtime, DEL_ENTRY) != 0){
					if(verbose_f)
						syslog(LOG_ERR, "gcollection_host_entries(: Error while logging new entry");

					return(-1);
				}

				if(del_host_entry(hlist, chentry) != 0){
					if(verbose_f)
						syslog(LOG_ERR, "gcollection_host_entries(): Error while eliminating host entry");

					return(-1);
				}
			}
		}
	}

	return 0;
}



/*
 * Function: send_host_probe()
 *
 * Sends a probe packet to a single IPv6 address
 */

int send_host_probe(pcap_t *pfd, struct iface_data *idata, unsigned char type, struct host_entry *host){
	volatile unsigned char	*ptr;

	unsigned int 			icmp6_max_packet_size;
	struct ether_header		*ether;
	unsigned char 			*v6buffer;
	struct ip6_hdr			*ipv6;
	struct in6_addr			targetaddr;
	struct ip6_dest			*destopth;
	struct ip6_opt			*opt;
	u_int32_t				*uint32;

	icmp6_max_packet_size = idata->mtu;
	ether = (struct ether_header *) wbuffer;
	v6buffer = (unsigned char *) ether + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	targetaddr= host->ip6;

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;
	ipv6->ip6_dst= targetaddr;
	ipv6->ip6_src= *src_addr_sel(idata, &(host->ip6));

	ether->src = idata->ether;
	ether->dst = host->ether;
	ether->ether_type = htons(0x86dd);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	switch(type){
		case PROBE_ICMP6_ECHO:
			*prev_nh = IPPROTO_ICMPV6;

			if( (ptr+sizeof(struct icmp6_hdr)+ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f)
					syslog(LOG_ERR, "send_host_probe(): Packet too large while creating ICMPv6 Echo Request "
									"Probe packet");

				return(-1);
			}

			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = rand();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(rand());		/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = rand();
				ptr += sizeof(u_int32_t);
			}
			break;

		case PROBE_UNREC_OPT:
			*prev_nh = IPPROTO_DSTOPTS;


			if( (ptr+sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f)
					syslog(LOG_ERR, "send_host_probe(): Packet too large while creating Unrec. Opt. Probe Packet");

				return(-1);
			}

			destopth = (struct ip6_dest *) ptr;
			destopth->ip6d_len= 0;
			destopth->ip6d_nxt= IPPROTO_ICMPV6;

			ptr= ptr + 2;
			opt= (struct ip6_opt *) ptr;
			opt->ip6o_type= 0x80;
			opt->ip6o_len= 4;

			ptr= ptr + 2;
			uint32 = (u_int32_t *) ptr;
			*uint32 = rand();

			ptr= ptr +4;
			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = rand();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(rand());		/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = rand();
				ptr += sizeof(u_int32_t);
			}
			break;
	}

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6));


	if((nw=pcap_inject(pfd, (unsigned char *) ether, ptr - (unsigned char *) ether)) == -1){
		if(verbose_f)
			syslog(LOG_ERR, "send_host_probe(): pcap_inject(): %s", pcap_geterr(pfd));

		return(-1);
	}

	if(nw != (ptr- (unsigned char *) ether)){
		if(verbose_f)
			syslog(LOG_ERR, "send_host_probe(): pcap_inject(): only wrote %lu bytes "
							"(rather than %lu bytes)", (LUI) nw, (LUI) (ptr- (unsigned char *) ether));
		return(-1);
	}

	return 0;
}



/*
 * Function: send_multicast_packet()
 *
 * Sends a probe packet to the "all nodes link-local" multicast address
 */

int send_multicast_packet(pcap_t *pfd, struct iface_data *idata, struct in6_addr *srcaddr, unsigned char type, \
							struct in6_addr *target){
	unsigned char			*ptr;
	unsigned int 			icmp6_max_packet_size;
	struct ether_header		*ether;
	unsigned char 			*v6buffer;
	struct ip6_hdr			*ipv6;
	struct ip6_dest			*destopth;
	struct ip6_opt			*opt;
	u_int32_t				*uint32;

	icmp6_max_packet_size = idata->mtu;
	ether = (struct ether_header *) wbuffer;
	v6buffer = (unsigned char *) ether + sizeof(struct ether_header);
	ipv6 = (struct ip6_hdr *) v6buffer;

	ipv6->ip6_flow=0;
	ipv6->ip6_vfc= 0x60;
	ipv6->ip6_hlim= 255;

	ipv6->ip6_src= *srcaddr;
	ipv6->ip6_dst= *target;

	ether->src = idata->ether;
	ether->dst = ether_multicast(&(ipv6->ip6_dst));
	ether->ether_type = htons(0x86dd);

	prev_nh = (unsigned char *) &(ipv6->ip6_nxt);

	ptr = (unsigned char *) v6buffer + MIN_IPV6_HLEN;

	switch(type){
		case PROBE_ICMP6_ECHO:
			*prev_nh = IPPROTO_ICMPV6;

			if( (ptr+sizeof(struct icmp6_hdr)+ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f)
					syslog(LOG_ERR, "send_multicast_packet(): Packet too large while creating ICMPv6 Echo "
									"Request Probe packet");

				return(-1);
			}

			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = rand();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(rand());		/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = rand();
				ptr += sizeof(u_int32_t);
			}
			break;

		case PROBE_UNREC_OPT:
			*prev_nh = IPPROTO_DSTOPTS;

			if( (ptr+sizeof(struct icmp6_hdr) + 8 + ICMPV6_ECHO_PAYLOAD_SIZE) > (v6buffer+icmp6_max_packet_size)){
				if(verbose_f)
					syslog(LOG_ERR, "send_multicast_packet(): Packet too large while creating Unrec. Opt. "
									"Probe Packet");

				return(-1);
			}

			destopth = (struct ip6_dest *) ptr;
			destopth->ip6d_len= 0;
			destopth->ip6d_nxt= IPPROTO_ICMPV6;

			ptr= ptr + 2;
			opt= (struct ip6_opt *) ptr;
			opt->ip6o_type= 0x80;
			opt->ip6o_len= 4;

			ptr= ptr + 2;
			uint32 = (u_int32_t *) ptr;
			*uint32 = rand();

			ptr= ptr +4;
			icmp6 = (struct icmp6_hdr *) ptr;
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6->icmp6_code = 0;
			icmp6->icmp6_cksum = rand();
			icmp6->icmp6_data16[0]= htons(getpid());	/* Identifier */
			icmp6->icmp6_data16[1]= htons(rand());		/* Sequence Number */

			ptr = ptr+ sizeof(struct icmp6_hdr);

			for(i=0; i<(ICMPV6_ECHO_PAYLOAD_SIZE>>2); i++){
				*(u_int32_t *)ptr = rand();
				ptr += sizeof(u_int32_t);
			}
			break;
	}

	ipv6->ip6_plen = htons((ptr - v6buffer) - MIN_IPV6_HLEN);
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in_chksum(v6buffer, icmp6, ptr-((unsigned char *)icmp6));

	if((nw=pcap_inject(pfd, (unsigned char *) ether, ptr - (unsigned char *) ether)) == -1){
		if(verbose_f)
			syslog(LOG_ERR, "send_multicast_packet(): pcap_inject(): %s", pcap_geterr(pfd));

		return(-1);
	}

	if(nw != (ptr- (unsigned char *) ether)){
		if(verbose_f)
			syslog(LOG_ERR, "send_multicast_packet(): pcap_inject(): only wrote %lu bytes "
							"(rather than %lu bytes)\n", (LUI) nw, (LUI) (ptr - (unsigned char *) ether));

		return(-1);
	}

	return 0;
}


/*
 * Function: send_multicast_probe()
 *
 * Sends a probe packet to the "all nodes link-local" multicast address
 */

int send_multicast_probe(pcap_t *pfd, struct iface_data *idata, struct host_list *hlist, unsigned char probetype){
	unsigned int	*state;
	unsigned int	*naddr;

	if(probetype == PROBE_ICMP6_ECHO){
		state= &(hlist->mc_echo_state);
		naddr= &(hlist->mc_echo_naddr);	
	}
	else{
		state= &(hlist->mc_unrec_state);
		naddr= &(hlist->mc_unrec_naddr);	
	}


	if( (*state == SCAN_GLOBAL) && (*naddr < idata->ip6_global.nprefix)){
		if(send_multicast_packet(pfd, idata, &((idata->ip6_global.prefix[*naddr])->ip6), probetype, &all_nodes_onlink) != 0){
			if(verbose_f)
				syslog(LOG_ERR, "send_multicast_probe(): Error when sending multicast probe to all-nodes "
								"link-local (src: link-local)");

			return(-1);
		}

		(*naddr)++;

		if(*naddr >= idata->ip6_global.nprefix)
			*state= SCAN_LOCAL;
	}
	else{
		if(send_multicast_packet(pfd, idata, &(idata->ip6_local), probetype, &all_nodes_onlink) != 0){
			if(verbose_f)
				syslog(LOG_ERR, "send_multicast_probe(): Error when sending multicast probe to all-nodes "
								"link-local (src: link-local)");

			return(-1);
		}

		*state= SCAN_GLOBAL;
		*naddr=0;
	}

	return 0;
}


/*
 * Function: log_hentry()
 *
 * Log a change in the status of an address
 */

int log_hentry(struct iface_data *idata, struct host_entry *hptr, time_t *timestamp, unsigned char status){
	char date[30];

	if(inet_ntop(AF_INET6, &(hptr->ip6), pv6addr, sizeof(pv6addr))<=0){
		if(verbose_f)
			syslog(LOG_ERR, "log_hentry(): inet_ntop(): Error converting IPv6 address to presentation format");

		return(-1);
	}

	if(ether_ntop( &(hptr->ether), plinkaddr, sizeof(plinkaddr)) == 0){
		if(verbose_f)
			syslog(LOG_ERR, "log_hentry(): ether_ntop(): Error converting address");

		return(-1);
	}

	switch(status){
		case(ADD_ENTRY):
			if(timestampf == TIMESTAMP_DATE){
				ctime_r(timestamp, date);
				date[24]=0;
				if(fprintf(fplog, "%s %s ADD_ADDR %s (%s)\n", date, idata->iface, pv6addr, plinkaddr) < 0){
					syslog(LOG_ERR, "Error while writting 'ADD_ADDR' message to IPv6 address log file");
					return(-1);
				}
			}
			else{
				if(fprintf(fplog, "%lu %s ADD_ADDR %s (%s)\n", (LUI) *timestamp, idata->iface, pv6addr, plinkaddr) < 0){
					syslog(LOG_ERR, "Error while writting 'ADD_ADDR' message to IPv6 address log file");
					return(-1);
				}
			}

			break;

		case(DEL_ENTRY):
			if(timestampf == TIMESTAMP_DATE){
				ctime_r(timestamp, date);
				date[24]=0;

				if(fprintf(fplog, "%s %s DEL_ADDR %s (%s)\n", date, idata->iface, pv6addr, plinkaddr) < 0){
					syslog(LOG_ERR, "Error while writting 'DEL_ADDR' message to IPv6 address log file");
					return(-1);
				}
			}
			else{
				if(fprintf(fplog, "%lu %s DEL_ADDR %s (%s)\n", (LUI) *timestamp, idata->iface, pv6addr, plinkaddr) < 0){
					syslog(LOG_ERR, "Error while writting 'DEL_ADDR' message to IPv6 address log file");
					return(-1);
				}
			}

			break;

		default:
			break;
	}

	fflush(fplog);
	return(0);
}


/*
 * Function: process_config_file()
 *
 * Processes the ipv6mon configuration file
 */

int process_config_file(const char *path){
	FILE *fp;
	char *key, *value;
	char line[MAX_LINE_SIZE];
	int	r;
	unsigned int ln=1;

	if( (fp=fopen(path, "r")) == NULL){
		if(verbose_f){
			if(showconfig_f)
				puts("process_config_file(): Error opening config file");
			else
				syslog(LOG_ERR, "process_config_file(): Error opening config file");
		}

		return(-1);
	}

	while(fgets(line, sizeof(line),  fp) != NULL){
		r=keyval(line, strlen(line), &key, &value);

		if(r == 1){
			if(strncmp(key, "NetworkInterface", MAX_VAR_NAME_LEN) == 0){
				strncpy(iface, value, IFACE_LENGTH-1);
				iface_f=1;
			}
			else if(strncmp(key, "AddressLogFile", MAX_VAR_NAME_LEN) == 0){
				if( (logfile= malloc(strlen(value)+1)) == NULL){
					if(verbose_f){
						if(showconfig_f)
							puts("process_config_file(): Error while allocating memory to store log file path");
						else
							syslog(LOG_ERR, "process_config_file(): Error while allocating memory to store log file path");
					}

					fclose(fp);
					return(-1);
				}

				strncpy(logfile, value, strlen(value)+1);
				logfile_f=1;
			}
			else if(strncmp(key, "LockFile", MAX_VAR_NAME_LEN) == 0){
				if( (lockfile= malloc(strlen(value)+1)) == NULL){
					if(verbose_f){
						if(showconfig_f)
							puts("process_config_file(): Error while allocating memory to store lock file path");
						else
							syslog(LOG_ERR, "process_config_file(): Error while allocating memory to store lock file path");
					}

					fclose(fp);
					return(-1);
				}

				strncpy(lockfile, value, strlen(value)+1);
				lockfile_f=1;
			}
			else if(strncmp(key, "UnprivilegedUser", MAX_VAR_NAME_LEN) == 0){
				if( (unprivuser= malloc(strlen(value)+1)) == NULL){
					if(verbose_f){
						if(showconfig_f)
							puts("process_config_file(): Error while allocating memory to store "
									"unprivileged username");
						else
							syslog(LOG_ERR, "process_config_file(): Error while allocating memory to store "
											"unprivileged username");
					}

					fclose(fp);
					return(-1);
				}

				strncpy(unprivuser, value, strlen(value)+1);
				unprivuser_f=1;
			}
			else if(strncmp(key, "UnprivilegedGroup", MAX_VAR_NAME_LEN) == 0){
				if( (unprivgroup= malloc(strlen(value)+1)) == NULL){
					if(verbose_f){
						if(showconfig_f)
							puts("process_config_file(): Error while allocating memory to store "
									"unprivileged group name");
						else
							syslog(LOG_ERR, "process_config_file(): Error while allocating memory to store "
											"unprivileged group name");
					}

					fclose(fp);
					return(-1);
				}

				strncpy(unprivgroup, value, strlen(value)+1);
				unprivgroup_f=1;
			}
			else if(strncmp(key, "MaxAddressEntries", MAX_VAR_NAME_LEN) == 0){
				maxaddrentries= (unsigned int) atoi(value);
				maxaddrentries_f=1;
			}
			else if(strncmp(key, "MaxCandidateEntries", MAX_VAR_NAME_LEN) == 0){
				maxcandentries= (unsigned int) atoi(value);
				maxcandentries_f=1;
			}
			else if(strncmp(key, "CandidateAddressTimeout", MAX_VAR_NAME_LEN) == 0){
				candaddrtimeout= (unsigned int) atoi(value);
				candaddrtimeout_f=1;
			}
			else if(strncmp(key, "AddressTimeout", MAX_VAR_NAME_LEN) == 0){
				addrtimeout= (unsigned int) atoi(value);
				addrtimeout_f=1;
			}
			else if(strncmp(key, "ProbeType", MAX_VAR_NAME_LEN) == 0){
				if(strncmp(value, "echo", strlen("echo")) == 0){
					probe_echo_f=1;
					probetype_f=1;
				}
				else if(strncmp(value, "unrec", strlen("unrec")) == 0){
					probe_unrec_f=1;
					probetype_f=1;
				}
				else if(strncmp(value, "all", strlen("all")) == 0){
					probe_echo_f=1;
					probe_unrec_f=1;
					probetype_f=1;
				}
				else{
					if(verbose_f){
						if(showconfig_f)
							puts("process_config_file(): Uknown ProbeType in configuration file");
						else
							syslog(LOG_ERR, "process_config_file(): Uknown ProbeType in configuration file");
					}

					fclose(fp);
					return(-1);
				}
			}
			else if(strncmp(key, "UnicastProbeInterval", MAX_VAR_NAME_LEN) == 0){
				unicastprobeint= (unsigned int) atoi(value);
				unicastprobeint_f=1;
			}
			else if(strncmp(key, "MaxUnprobedInterval", MAX_VAR_NAME_LEN) == 0){
				maxunprobedint= (unsigned int) atoi(value);
				maxunprobedint_f=1;
			}
			else if(strncmp(key, "McastEchoProbeInterval", MAX_VAR_NAME_LEN) == 0){
				mcechoprobeint= (unsigned int) atoi(value);
				mcechoprobeint_f=1;
			}
			else if(strncmp(key, "McastUnrecProbeInterval", MAX_VAR_NAME_LEN) == 0){
				mcunrecprobeint= (unsigned int) atoi(value);
				mcunrecprobeint_f=1;
			}
			else if(strncmp(key, "TimestampFormat", MAX_VAR_NAME_LEN) == 0){
				if(strncmp(value, "date", strlen("date")) == 0){
					timestampf= TIMESTAMP_DATE;
					timestampf_f=1;
				}
				else if(strncmp(value, "epoch", strlen("epoch")) == 0){
					timestampf= TIMESTAMP_EPOCH;
					timestampf_f=1;
				}
				else{
					if(verbose_f){
						if(showconfig_f)
							puts("process_config_file(): Uknown TimestampFormat");
						else
							syslog(LOG_ERR, "process_config_file(): Uknown TimestampFormat");
					}

					fclose(fp);
					return(-1);
				}
			}

		}
		else if(r == -1){
			if(verbose_f){
				if(showconfig_f)
					printf("process_config_file(): Error in line %u of configuration file\n", ln);
				else
					syslog(LOG_ERR, "process_config_file(): Error in line %u of configuration file", ln);
			}

			fclose(fp);
			return(-1);
		}

		ln++;
	}

	fclose(fp);

	if(!logfile_f)
		logfile="/var/log/ipv6mon.log";

	if(!lockfile_f)
		lockfile="/var/run/ipv6mon.pid";

	if(!unprivuser_f)
		unprivuser="ipv6mon";

	if(!unprivgroup_f)
		unprivgroup="ipv6mon";

	if(!maxaddrentries_f)
		maxaddrentries= MAX_ADDR_ENTRIES;

	if(!maxcandentries_f){
		maxcandentries= maxaddrentries/4;

		if(maxcandentries < MIN_ADDR_ENTRIES)
			maxcandentries= MIN_ADDR_ENTRIES;
	}

	if(!addrtimeout_f)
		addrtimeout= ADDR_TIMEOUT;

	if(!candaddrtimeout_f){
		if(addrtimeout > CAND_ADDR_TIMEOUT)
			candaddrtimeout= CAND_ADDR_TIMEOUT;
		else
			candaddrtimeout= addrtimeout;
	}

	if(!maxunprobedint_f)
		maxunprobedint= MAX_UNPROBED_INTERVAL;

	if(!unicastprobeint_f)
		unicastprobeint= UNICAST_PROBE_INTERVAL;

	if(!mcechoprobeint_f)
		mcechoprobeint= MC_ECHO_PROBE_INTERVAL;

	if(!mcunrecprobeint_f)
		mcunrecprobeint= MC_UNREC_PROBE_INTERVAL;

	if(!timestampf_f)
		timestampf= TIMESTAMP_DATE;

	if(!probetype_f){
		probe_echo_f=1;
		probe_unrec_f=1;
		probetype_f=1;
	}

	if(strncmp(unprivuser, "root", MAX_VAR_NAME_LEN) == 0){
		if(showconfig_f)
			puts("process_config_file(): UnprivilegedUser cannot be set to 'root'");
		else
			syslog(LOG_ERR, "process_config_file(): UnprivilegedUser cannot be set to 'root'");

		return(-1);
	}

	if(maxaddrentries <= MIN_ADDR_ENTRIES){
		if(showconfig_f)
			puts("process_config_file(): MaxAddressEntries too small");
		else
			syslog(LOG_ERR, "process_config_file(): MaxAddressEntries too small");

		return(-1);
	}

	if(maxcandentries >= maxaddrentries){
		if(showconfig_f)
			puts("process_config_file(): Incompatible MaxAddressEntries and MaxCandidateEntries values");
		else
			syslog(LOG_ERR, "process_config_file(): Incompatible MaxAddressEntries and MaxCandidateEntries values");

		return(-1);
	}

	if(maxunprobedint > addrtimeout){
		if(showconfig_f)
			puts("process_config_file(): Incompatible MaxUnprobedInterval and AddressTimeout values");
		else
			syslog(LOG_ERR, "process_config_file(): Incompatible MaxUnprobedInterval and AddressTimeout values");

		return(-1);
	}

	if(unicastprobeint < MIN_UNICAST_PROBE_INTERVAL){
		if(showconfig_f)
			puts("process_config_file(): UnicastProbeInterval value too small");
		else
			syslog(LOG_ERR, "process_config_file(): UnicastProbeInterval value too small");

		return(-1);
	}

	if(mcechoprobeint < MIN_MC_ECHO_PROBE_INTERVAL){
		if(showconfig_f)
			puts("process_config_file(): McastEchoProbeInterval value too small");
		else
			syslog(LOG_ERR, "process_config_file(): McastEchoProbeInterval value too small");

		return(-1);
	}

	if(mcunrecprobeint < MIN_MC_UNREC_PROBE_INTERVAL){
		if(showconfig_f)
			puts("process_config_file(): McastEchoProbeInterval value too small");
		else
			syslog(LOG_ERR, "process_config_file(): McastEchoProbeInterval value too small");

		return(-1);
	}

	return(0);
}


/*
 * Function: keyval()
 *
 * Obtains a (variable, value) pair from a line of text in "variable=value # comments" format
 */

int keyval(char *line, unsigned int len, char **key, char **val){
	char *ptr;
	ptr= line;

	/* Skip initial spaces (e.g. "   variable=value") */
	while( (*ptr==' ' || *ptr=='\t') && ptr < (line+len))
		ptr++;

	/* If we got to end of line or there is a comment or equal sign, there is no (variable, value) pair) */
	if(ptr==(line+len) || *ptr=='#' || *ptr=='=' || *ptr=='\r' || *ptr=='\n')
		return 0;

	*key=ptr;

	/* The variable name is everything till (and excluding) the first separator character (e.g., space or tab) */
	while( (*ptr!=' ' && *ptr!='\t' && *ptr!='\r' && *ptr!='\n' && *ptr!='#' && *ptr!='=') && ptr < (line+len))
		ptr++;

	/*
	   If the variable name is followed by a comment sign, or occupies the entire line, there's an error
	   in the config file (i.e., there is no "variable=value" pair)
	 */
	if(ptr==(line+len) || *ptr=='#' || *ptr=='\r' || *ptr=='\n')
		return -1;


	if(*ptr==' ' || *ptr=='\t'){
		/* The variable name is followed by spaces -- skip them, and find the "equal to" sign */
		*ptr=0; /* NULL-terminate the key */
		ptr++;

		while(ptr<(line+len) &&  (*ptr==' ' || *ptr=='\t'))
			ptr++;

		if(ptr==(line+len) || *ptr!='=')
			return -1;

		ptr++;
	}else{
		/* The variable name is followed by the "equal to" sign */
		*ptr=0; 
		ptr++;
	}

	/*
	   If the equal sign is followed by spaces, skip them
	 */
	while( (*ptr==' ' || *ptr=='\t') && ptr<(line+len))
		ptr++;

	/* We found the "value" in the "variable=value" pair */
	*val=ptr;

	/* The value is everthing till (and excluding) the first separator character */
	while( (*ptr!='#' && *ptr!='\r' && *ptr!='\n' && *ptr!='\t' && *ptr!='=' && *ptr!=' ') && ptr < (line+len))
		ptr++;

	/* If the value string was actually "empty", we return an error */
	if(ptr == *val)
		return(-1);

	*ptr=0;
	return(1);
}


/*
 * Function: make_daemon()
 *
 * Makes the current program become a daemon
 */

int make_daemon(void){
	pid_t				pid;
	int					fd0, fd1, fd2;
	struct rlimit		r1;
	struct sigaction	sa;

	/*
	   Set the umask such that "group" and "others" can only (by default) read files
	   (e.g. the lockfile)
	 */
	umask(S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH);

	if(getrlimit(RLIMIT_NOFILE, &r1) < 0){
		if(verbose_f)
			syslog(LOG_ERR, "make_daemon(): Cannot get file limit");

		return(-1);
	}

	if( (pid=fork()) < 0){
		if(verbose_f)
			syslog(LOG_ERR, "make_daemon(): Error while forking first process");

		return(-1);		
	}
	else if(pid != 0){
		exit(0);
	}

	setsid();

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGHUP, &sa, NULL) < 0){
		if(verbose_f)
			syslog(LOG_ERR, "make_daemon(): Error when setting handler for SIGHUP");

		return(-1);
	}

	if((pid=fork()) < 0){
		if(verbose_f)
			puts("make_daemon(): Error when forking second process");

		return(-1);
	}
	else if(pid != 0){
		exit(0);
	}

	if(chdir("/") < 0){
		if(verbose_f)
			syslog(LOG_ERR, "Error while changing current working directory");

		return(-1);
	}

	if(r1.rlim_max == RLIM_INFINITY)
		r1.rlim_max = 1024;

	for(i=0; i < r1.rlim_max; i++)
		close(i);

	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	if(fd0 != 0 || fd1 != 1 || fd2 != 2){
		if(verbose_f)
			syslog(LOG_ERR, "Unexpected descriptors (%d, %d, %d) when opening to /dev/null", fd0, fd1, fd2);

		return(-1);
	}

	return 0;
}


/*
 * Function: already_running()
 *
 * Check whether another instance of the daemon is already running
 */

int already_running(void){
	struct flock fl;
	int fd;
	char buffer[100];

	if( (fd=open(lockfile, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0){
		if(verbose_f)
			syslog(LOG_ERR, "already_running(): open(): %m");

		return(-1);
	}

	fl.l_type= F_WRLCK;
	fl.l_start= 0;
	fl.l_whence= SEEK_SET;
	fl.l_len= 0;

	if(fcntl(fd, F_SETLK, &fl) == -1){
		if(errno==EACCES || errno==EAGAIN){
			close(fd);
			return 1;
		}
		else{
			close(fd);
			return(-1);
		}
	}

	if(ftruncate(fd, 0) == -1){
		if(verbose_f)
			syslog(LOG_ERR, "already_running(): ftruncate(): %m");

		close(fd);
		return(-1);
	}

	if(snprintf(buffer, 100, "%lu", (LUI) getpid()) < 0){
		if(verbose_f)
			syslog(LOG_ERR, "already_running(): snprintf(): %m");

		close(fd);
		return(-1);
	}

	if(write(fd, buffer, strlen(buffer)+1) == -1){
		if(verbose_f)
			syslog(LOG_ERR, "already_running(): write(): %m");

		close(fd);
		return(-1);
	}

	return 0;
}


/*
 * Function: log_start()
 *
 * Records to the address log and to syslog that ipv6mon is starting
 */

int log_start(struct iface_data *idata){
	time_t		curtime;
	char 		date[30];

	curtime= time(NULL);

	if(timestampf == TIMESTAMP_DATE){
		ctime_r(&curtime, date);
		date[24]=0;

		if(fprintf(fplog, "%s %s INI_ADDR (Start logging IPv6 addresses)\n", date, idata->iface) < 0){
			if(verbose_f)
				syslog(LOG_ERR, "log_start(): fprintf(): %s", strerror(errno));

			return(-1);
		}
		else{
			fflush(fplog);
		}
	}
	else{
		if(fprintf(fplog, "%lu %s INI_ADDR (Start logging IPv6 addresses)\n", (LUI) curtime, idata->iface) < 0){
			if(verbose_f)
				syslog(LOG_ERR, "log_start(): fprintf(): %s", strerror(errno));

			return(-1);
		}
		else{
			fflush(fplog);
		}
	}

	syslog(LOG_INFO, "Starting IPv6 address monitoring on %s", idata->iface);
	return 0;
}


/*
 * Function: log_stop()
 *
 * Logs to the address log and to syslog that ipv6mon is stopping
 */

int log_stop(struct iface_data *idata){
	time_t		curtime;
	char 		date[30];

	curtime= time(NULL);

	if(timestampf == TIMESTAMP_DATE){
		ctime_r(&curtime, date);
		date[24]=0;

		if(fprintf(fplog, "%s %s STP_ADDR (Stopping IPv6 address monitoring)\n", date, idata->iface) < 0){
			syslog(LOG_ERR, "Error writing to address log while shutting down");
			return(-1);
		}
	}
	else{
		if(fprintf(fplog, "%lu %s STP_ADDR (Stopping IPv6 address monitoring)\n", (LUI) curtime, idata->iface) < 0){
			syslog(LOG_ERR, "Error writing to address log while shutting down");
			return(-1);
		}
	}

	syslog(LOG_INFO, "Stopping IPv6 address monitoring on %s", idata->iface);
	return 0;
}


/*
 * Function: sig_term()
 *
 * Handler for the SIGTERM signal. Sets a flag such that the main loop records in the address log 
 * and to syslog that ipv6mon is being shut down.
 */

void sigterm(int signo){
	shutdown_f= 1;
}

