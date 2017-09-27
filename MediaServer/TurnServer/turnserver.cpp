#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include "conf.h"
#include "protocol.h"
#include "allocation.h"
#include "account.h"
#include "tls_peer.h"
#include "util_sys.h"
#include "util_crypto.h"
#include "dbg.h"
#include "turnserver.h"
#include "mod_tmpuser.h"

#include "../UdpServer/Udp_Handler.h"
#include "../public/config.h"

struct list_head* allocation_list_tmp;
void PrintAllocationList();

#ifndef HAVE_SIGACTION
/* expiration stuff use real-time signals
 * that can only be handled by sigaction
 * so stop compilation with error
 */
//#error "Must have sigaction."
#endif

/* for operating systems that support setting
 * DF flag from userspace, give them a
 * #define OS_SET_DF_SUPPORT
 */
#if defined(__linux__)
/**
 * \def OS_SET_DF_SUPPORT
 * \brief Current operating system can set the DF flag.
 */
#define OS_SET_DF_SUPPORT 1
#endif

/**
 * \def SOFTWARE_DESCRIPTION
 * \brief Textual description of the server.
 */
#define SOFTWARE_DESCRIPTION "TurnServer "
#define PACKAGE_VERSION "1.0"

/**
 * \def DEFAULT_CONFIGURATION_FILE
 * \brief Default configuration file pathname.
 */
#define DEFAULT_CONFIGURATION_FILE "/etc/turnserver.conf"

/**
 * \var g_run
 * \brief Running state of the program.
 */
static volatile sig_atomic_t g_run = 0;

/**
 * \var g_reinit
 * \brief Reload credentials (parse again account file).
 */
static volatile sig_atomic_t g_reinit = 0;

/**
 * \var g_expired_allocation_list
 * \brief List which constains expired allocation.
 */
static struct list_head g_expired_allocation_list;

/**
 * \var g_expired_permission_list
 * \brief List which constains expired permissions.
 */
static struct list_head g_expired_permission_list;

/**
 * \var g_expired_channel_list
 * \brief List which constains expired channels.
 */
static struct list_head g_expired_channel_list;

/**
 * \var g_expired_token_list
 * \brief List which contains expired tokens.
 */
static struct list_head g_expired_token_list;

/**
 * \var g_expired_tcp_relay_list
 * \brief List which contains expired TCP relays.
 */
//static struct list_head g_expired_tcp_relay_list;

/**
 * \var g_token_list
 * \brief List of valid tokens.
 */
//static struct list_head g_token_list;

/**
 * \var g_denied_address_list
 * \brief The denied address list.
 */
//static struct list_head g_denied_address_list;

/**
 * \var g_supported_even_port_flags
 * \brief EVEN-PORT flags supported.
 *
 * For the moment the following flags are supported:
 * - R: reserve couple of ports (one even, one odd).
 */
static const uint8_t g_supported_even_port_flags = 0x80;

/**
 * \var g_tcp_socket_list
 * \brief List which contains remote TCP sockets.
 *
 * This list does not contains TURN-TCP related sockets.
 */
//static struct list_head g_tcp_socket_list;


/**
 * \brief Get sockaddr structure size according to its type.
 * \param ss sockaddr_storage structure
 * \return size of sockaddr_in or sockaddr_in6
 */
static inline socklen_t sockaddr_get_size(struct sockaddr_storage* ss) {
	/* assume address type is IPv4 or IPv6 as TURN specification
	 * supports only these two types of address
	 */
	return (ss->ss_family == AF_INET) ? sizeof(struct sockaddr_in)
			: sizeof(struct sockaddr_in6);
}

/**
 * \brief Signal management.
 * \param code signal code
 */
static void signal_handler(int code) {
	switch (code) {
	case SIGUSR1:
	case SIGUSR2:
	case SIGPIPE:
		break;
	case SIGHUP:
		g_reinit = 1;
		break;
	case SIGINT:
	case SIGTERM:
		/* stop the program */
		g_run = 0;
		break;
	default:
		break;
	}
}

/**
 * \brief Realtime signal management.
 *
 * This is mainly used when a object timer expired. As usage of functions like
 * free() in a signal handler are not permitted and to avoid race conditions,
 * this function put the desired expired object in an expired list and the main
 * loop will purge it.
 * \param signo signal number
 * \param info additionnal info
 * \param extra not used
 */
static void realtime_signal_handler(int signo, siginfo_t* info, void* extra) {
	/* to avoid compilation warning because it is not used */
	(void) extra;

	if (!g_run) {
		/* if the program will exit, do not care about signals */
		return;
	}

	debug(DBG_ATTR, "Realtime signal received\n");

	if(signo == SIGRT_EXPIRE_ALLOCATION)
	{
		struct allocation_desc* desc = info->si_value.sival_ptr;

		if(!desc)
		{
			return;
		}

		debug(DBG_ATTR, "Allocation expires: %p\n", desc);
		/* add it to the expired list, the next loop will
		 * purge it
		 */
		LIST_ADD(&desc->list2, &g_expired_allocation_list);
	}
	else if(signo == SIGRT_EXPIRE_PERMISSION)
	{
		struct allocation_permission* desc = info->si_value.sival_ptr;

		if(!desc)
		{
			return;
		}

		debug(DBG_ATTR, "Permission expires: %p\n", desc);
		/* add it to the expired list */
		LIST_ADD(&desc->list2, &g_expired_permission_list);
	}
	else if(signo == SIGRT_EXPIRE_CHANNEL)
	{
		struct allocation_channel* desc = info->si_value.sival_ptr;

		if(!desc)
		{
			return;
		}

		debug(DBG_ATTR, "Channel expires: %p\n", desc);
		/* add it to the expired list */
		LIST_ADD(&desc->list2, &g_expired_channel_list);
	}
	else if(signo == SIGRT_EXPIRE_TOKEN)
	{
		struct allocation_token* desc = info->si_value.sival_ptr;

		if(!desc)
		{
			return;
		}

		debug(DBG_ATTR, "Token expires: %p\n", desc);
		/* add it to the expired list */
		LIST_ADD(&desc->list2, &g_expired_token_list);
	}
	else if(signo == SIGRT_EXPIRE_TCP_RELAY)
	{
		//    struct allocation_tcp_relay* desc = info->si_value.sival_ptr;
			//
			//    if(!desc)
			//    {
			//      return;
			//    }
			//
			//    /* remove relay from list */
			//    debug(DBG_ATTR, "TCP relay expires: %p\n", desc);
			//    LIST_ADD(&desc->list2, &g_expired_tcp_relay_list);
		}
	}

	/**
	 * \brief Block realtime signal used in TurnServer.
	 *
	 * This is used to prevent race conditions when adding or removing objects in
	 * expired list (which is mainly done in signal handler and in purge loop).
	 */
static inline void turnserver_block_realtime_signal(void) {
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
	sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
	sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
	sigaddset(&mask, SIGRT_EXPIRE_TOKEN);
	sigprocmask(SIG_BLOCK, &mask, NULL);
}

/**
 * \brief Unblock realtime signal used in TurnServer.
 *
 * This is used to prevent race conditions when adding or removing objects in
 * expired list (which is mainly done in signal handler and in purge loop).
 */
static inline void turnserver_unblock_realtime_signal(void) {
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
	sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
	sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
	sigaddset(&mask, SIGRT_EXPIRE_TOKEN);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

/**
 * \brief Print help menu.
 * \param name name of the program
 * \param version version of the program
 */
static void turnserver_print_help(const char* name, const char* version) {
	fprintf(stdout, "TurnServer %s\n", version);
	fprintf(stdout, "Usage: %s [-c file] [-p pidfile] [-h] [-v]\n", name);
}

/**
 * \brief Parse the command line arguments.
 * \param argc number of argument
 * \param argv array of argument
 * \param configuration_file configuration (-c) argument will be filled in if
 * any
 * \param pid_file pid file (-p) argument will be filled in if any
 */
static void turnserver_parse_cmdline(int argc, char** argv,
		char** configuration_file, char** pid_file) {
	static const char* optstr = "c:p:hv";
	int s = 0;

	while ((s = getopt(argc, argv, optstr)) != -1) {
		switch (s) {
		case 'h': /* help */
			//        turnserver_print_help(argv[0], PACKAGE_VERSION);
			//        exit(EXIT_SUCCESS);
			break;
		case 'v': /* version */
			fprintf(stdout, "TurnServer %s\n", PACKAGE_VERSION);
			fprintf(stdout, "Copyright (C) 2008-2012 Sebastien Vincent.\n");
			fprintf(stdout,
					"This is free software; see the source for copying "
						"conditions.  There is NO\n");
			fprintf(stdout,
					"warranty; not even for MERCHANTABILITY or FITNESS FOR "
						"A PARTICULAR PURPOSE.\n\n");
			exit(EXIT_SUCCESS);
		case 'c': /* configuration file */
			if (optarg) {
				*configuration_file = optarg;
			}
			break;
		case 'p': /* pid file */
			if (optarg) {
				*pid_file = optarg;
			}
			break;
		default:
			break;
		}
	}
}

#ifdef NDEBUG

/**
 * \brief Disable core dump if the server crash.
 *
 * Typically it is used in release mode. It prevents
 * user/attacker to have access to core dump which could
 * contains some sensitive data.
 */
static void turnserver_disable_core_dump(void)
{
	struct rlimit limit;

	limit.rlim_cur = 0;
	limit.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &limit);
}

#endif

/**
 * \brief Check bandwidth limitation on uplink OR downlink.
 * \param desc allocation descriptor
 * \param byteup byte received on uplink connection. 0 means bandwidth check
 * will be made on downlink (if different than 0)
 * \param bytedown byte received on downlink connection. 0 means bandwidth check
 * will be made on uplink (if different than 0)
 * \return 1 if bandwidth threshold is exceeded, 0 otherwise
 */
static int turnserver_check_bandwidth_limit(struct allocation_desc* desc,
		size_t byteup, size_t bytedown) {
	struct timeval now;
	unsigned long diff = 0;
	unsigned long d = 150; //turnserver_cfg_bandwidth_per_allocation();bandwidth_per_allocation

	if (d <= 0) {
		/* bandwidth quota disabled */
		return 0;
	}

	/* check in ms */
	gettimeofday(&now, NULL);

	if (byteup) {
		if (desc->bucket_tokenup < desc->bucket_capacity) {
			/* count in milliseconds */
			diff = (now.tv_sec - desc->last_timeup.tv_sec) * 1000
					+ (now.tv_usec - desc->last_timeup.tv_usec) / 1000;
			d *= diff;
			desc->bucket_tokenup = MIN(desc->bucket_capacity,
					desc->bucket_tokenup + d);
			gettimeofday(&desc->last_timeup, NULL);
		}

		debug(DBG_ATTR, "Tokenup bucket available: %u, tokens requested: %u\n",
		desc->bucket_tokenup, byteup);

		if(byteup <= desc->bucket_tokenup)
		{
			desc->bucket_tokenup -= byteup;
		}
		else
		{
			/* bandwidth exceeded */
			return 1;
		}
	}
	else if(bytedown)
	{
		if(desc->bucket_tokendown < desc->bucket_capacity)
		{
			/* count in milliseconds */
			diff = (now.tv_sec - desc->last_timedown.tv_sec) * 1000 +
			(now.tv_usec - desc->last_timedown.tv_usec) / 1000;
			d *= diff;
			desc->bucket_tokendown = MIN(desc->bucket_capacity,
					desc->bucket_tokendown + d);
			gettimeofday(&desc->last_timedown, NULL);
		}

		debug(DBG_ATTR,"Tokendown bucket available: %u, tokens requested: %u\n",
        desc->bucket_tokendown, bytedown);

    if(bytedown <= desc->bucket_tokendown)
    {
      desc->bucket_tokendown -= bytedown;
    }
    else
    {
      /* bandwidth exceeded */
      return 1;
    }
  }

		/* bandwidth quota not reached */
		return 0;
	}

	/**
	 * \brief Verify if the address is an IPv6 tunneled ones.
	 * \param addr address to check
	 * \param addrlen sizeof address
	 * \return 1 if address is an IPv6 tunneled ones, 0 otherwise
	 */
static int turnserver_is_ipv6_tunneled_address(const uint8_t* addr,
		size_t addrlen) {
	if (addrlen == 16) {
		static const uint8_t addr_6to4[2] = { 0x20, 0x02 };
		static const uint8_t addr_teredo[4] = { 0x20, 0x01, 0x00, 0x00 };

		/* 6to4 or teredo address ? */
		if (!memcmp(addr, addr_6to4, 2) || !memcmp(addr, addr_teredo, 4)) {
			return 1;
		}
	}
	return 0;
}

TurnServer::TurnServer(Udp_Handle* pHandler)
{
	m_pHandler = pHandler;
	init_turnserver();
}

/**
 * \brief Send a TURN Error response.
 * \param transport_protocol transport protocol to send the message
 * \param sock socket
 * \param method STUN/TURN method
 * \param id transaction ID
 * \param saddr address to send
 * \param saddr_size sizeof address
 * \param error error code
 * \param speer TLS peer, if not NULL, send the error in TLS
 * \param key MD5 hash of account, if present, MESSAGE-INTEGRITY will be added
 * \note Some error codes cannot be sent using this function (420, 438, ...).
 * \return 0 if success, -1 otherwise
 */
int TurnServer::turnserver_send_error(int transport_protocol, int sock,
		int method, const uint8_t* id, int error, const struct sockaddr* saddr,
		socklen_t saddr_size, struct tls_peer* speer, unsigned char* key) {
	struct iovec iov[16]; /* should be sufficient */
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	size_t idx = 0;

	switch (error) {
	case 400: /* Bad request */
		hdr = turn_error_response_400(method, id, &iov[idx], &idx);
		break;
	case 403: /* Forbidden */
		hdr = turn_error_response_403(method, id, &iov[idx], &idx);
		break;
	case 437: /* Alocation mismatch */
		hdr = turn_error_response_437(method, id, &iov[idx], &idx);
		break;
	case 440: /* Address family not supported */
		hdr = turn_error_response_440(method, id, &iov[idx], &idx);
		break;
	case 441: /* Wrong credentials */
		hdr = turn_error_response_441(method, id, &iov[idx], &idx);
		break;
	case 442: /* Unsupported transport protocol */
		hdr = turn_error_response_442(method, id, &iov[idx], &idx);
		break;
	case 443: /* Peer address family mismatch */
		hdr = turn_error_response_443(method, id, &iov[idx], &idx);
		break;
	case 446: /* Connection already exists (RFC6062) */
		hdr = turn_error_response_446(method, id, &iov[idx], &idx);
		break;
	case 447: /* Connection timeout or failure (RFC6062) */
		hdr = turn_error_response_447(method, id, &iov[idx], &idx);
		break;
	case 486: /* Allocation quota reached */
		hdr = turn_error_response_486(method, id, &iov[idx], &idx);
		break;
	case 500: /* Server error */
		hdr = turn_error_response_500(method, id, &iov[idx], &idx);
		break;
	case 508: /* Insufficient port capacity */
		hdr = turn_error_response_508(method, id, &iov[idx], &idx);
		break;
	default:
		break;
	}

	if (!hdr) {
		return -1;
	}

	/* software (not fatal if it cannot be allocated) */
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
			sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx]))) {
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if (key) {
		if (turn_add_message_integrity(iov, &idx, key, 16, 1) == -1) {
			/* MESSAGE-INTEGRITY option has to be in message, so
			 * deallocate ressources and return
			 */
			iovec_free_data(iov, idx);
			return -1;
		}
		/* function above already set turn_msg_len field to big endian */
	} else {
		turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

		/* convert to big endian */
		hdr->turn_msg_len = htons(hdr->turn_msg_len);
	}

	//  /* finally send the response */
	//  if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
	//        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
	//      == -1)
	//  {
	//    debug(DBG_ATTR, "turn_send_message_asyn failed\n");
	//  }
	m_pHandler->handle_async_write((unsigned char*) &iov, idx);

	iovec_free_data(iov, idx);
	return 0;
}

/**
 * \brief Process a STUN Binding request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int TurnServer::turnserver_process_binding_request(int transport_protocol,
		int sock, const struct turn_message* message,
		const struct sockaddr* saddr, socklen_t saddr_size,
		struct tls_peer* speer)
{
	debug(DBG_ATTR, "Binding request received!\n");

	struct iovec iov[4]; /* header, software, xor-address, fingerprint */
	size_t idx = 0;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;

	if(!(hdr = turn_msg_binding_response_create(0, message->msg->turn_msg_id,
          &iov[idx])))
	{
		return -1;
	}
	idx++;

	if(!(attr = turn_attr_xor_mapped_address_create(saddr, STUN_MAGIC_COOKIE,
          message->msg->turn_msg_id, &iov[idx])))
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING,
			message->msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
		return -1;
	}
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

	/* software (not fatal if it cannot be allocated) */
	if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		  sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	/* NOTE: maybe add a configuration flag to enable/disable fingerprint in
	* output message
	*/
	/* add a fingerprint */
	if(!(attr = turn_attr_fingerprint_create(0, &iov[idx])))
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING,
				message->msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
		return -1;
	}
	hdr->turn_msg_len += iov[idx].iov_len;
	idx++;

	/* compute fingerprint */
	hdr->turn_msg_len = htons(hdr->turn_msg_len);
	/* do not take into account the attribute itself */
	((struct turn_attr_fingerprint*)attr)->turn_attr_crc =
				htonl(turn_calculate_fingerprint(iov, idx - 1));
	((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^=
				htonl(STUN_FINGERPRINT_XOR_VALUE);

	if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
	{
		debug(DBG_ATTR, "turn_send_message_asyn failed\n");
	}
	iovec_free_data(iov, idx);
	return 0;
}

	/**
	 * \brief Process a TURN ChannelData.
	 * \param transport_protocol transport protocol used
	 * \param channel_number channel number
	 * \param buf raw data (including ChannelData header)
	 * \param buflen length of the data
	 * \param saddr source address (TURN client)
	 * \param daddr destination address (TURN server)
	 * \param saddr_size sizeof address
	 * \param allocation_list list of allocations
	 * \return 0 if success, -1 otherwise
	 */
int TurnServer::turnserver_process_channeldata(int transport_protocol,
		uint16_t channel_number, const char* buf, ssize_t buflen,
		const struct sockaddr* saddr, const struct sockaddr* daddr,
		socklen_t saddr_size, struct list_head* allocation_list)
{
	ssize_t nb = -1;
	int optval = 0;
	int save_val = 0;
	socklen_t optlen = sizeof(int);


	debug(DBG_ATTR, "ChannelData received!\n");

	struct turn_channel_data* channel_data = (struct turn_channel_data*)buf;
	size_t len = ntohs(channel_data->turn_channel_len);

	if(len > (buflen - sizeof(struct turn_channel_data)))
	{
		/* length mismatch */
		debug(DBG_ATTR, "Length too big\n");
		return -1;
	}

	char* msg = (char*)channel_data->turn_channel_data;

	if(channel_number > 0x7FFF)
	{
		/* channel reserved for future use */
		debug(DBG_ATTR, "Channel number reserved for future use!\n");
		return -1;
	}

	struct allocation_desc* desc = allocation_list_find_tuple(allocation_list, transport_protocol, daddr,
      saddr, saddr_size);
	if(!desc)
	{
		/* not found */
		debug(DBG_ATTR, "No allocation found\n");
		return -1;
	}

	if(desc->relayed_transport_protocol != IPPROTO_UDP)
	{
 	  /* ignore for TCP relayed allocation */
		debug(DBG_ATTR,
        "ChannelData does not intend to work with TCP relayed address!");
		return -1;
	}

	struct allocation_channel* alloc_channel = allocation_desc_find_channel_number(desc, channel_number);

	if(!alloc_channel)
	{
		/* no channel bound to this peer */
		debug(DBG_ATTR, "No channel bound to this peer\n");
		return -1;
	}

	if(desc->relayed_addr.ss_family != alloc_channel->family)
	{
		debug(DBG_ATTR, "Could not relayed from a different family\n");
		return -1;
	}

	/* check bandwidth limit */
	if(turnserver_check_bandwidth_limit(desc, 0, len))
	{
		debug(DBG_ATTR, "Bandwidth quotas reached!\n");
		return -1;
	}

	uint8_t* peer_addr = alloc_channel->peer_addr;
	uint16_t peer_port = alloc_channel->peer_port;

	struct sockaddr_storage storage;
	switch(desc->relayed_addr.ss_family)
	{
	case AF_INET:
	  ((struct sockaddr_in*)&storage)->sin_family = AF_INET;
	  memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
	  ((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
	  memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
		  sizeof((struct sockaddr_in*)&storage)->sin_zero);
	  break;
	case AF_INET6:
	  ((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
	  memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
	  ((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
	  ((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
	  ((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
	#ifdef SIN6_LEN
	  ((struct sockaddr_in6*)&storage)->sin6_len = sizeof(struct sockaddr_in6);
	#endif
	  break;
	default:
	  return -1;
	  break;
	}

	/* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
	* server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
	*/
	if(desc->relayed_addr.ss_family == AF_INET &&
     (desc->tuple.client_addr.ss_family == AF_INET ||
      (desc->tuple.client_addr.ss_family == AF_INET6 &&
      IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&desc->tuple.client_addr)->sin6_addr))))
	{
	#ifdef OS_SET_DF_SUPPORT
		/* alternate behavior */
		optval = IP_PMTUDISC_DONT;

		if(!getsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
			  &optlen))
		{
		  setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
			  sizeof(int));
		}
		else
		{
		  /* little hack for not setting the old value of *_MTU_DISCOVER after
		   * sending message in case getsockopt failed
		   */
		  optlen = 0;
		}
	#else
		/* avoid compilation warning */
		optval = 0;
		optlen = 0;
		save_val = 0;
	#endif
	}

	char buf1[INET6_ADDRSTRLEN] = {0};
	memset(buf1, 0, sizeof(buf1));
	inet_ntop(AF_INET, peer_addr, buf1, INET6_ADDRSTRLEN);

	char buf10[INET6_ADDRSTRLEN] = {0};
	memset(buf10, 0, sizeof(buf10));
    inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, buf10, INET6_ADDRSTRLEN);
    int port10 = ntohs((((struct sockaddr_in*)saddr)->sin_port));

	char buf11[INET6_ADDRSTRLEN] = {0};
    memset(buf11, 0, sizeof(buf11));
    inet_ntop(AF_INET, &(((struct sockaddr_in*)daddr)->sin_addr), buf11, INET6_ADDRSTRLEN);
    int port11 = ntohs((((struct sockaddr_in*)daddr)->sin_port));

    debug(DBG_ATTR, "saddr_ip = %s, saddr_port = %d, daddr_ip = %s, daddr_port = %d, relay_ip = %s, relay_port = %d\n",buf10, port10, buf11, port11, buf1, peer_port);


    debug(DBG_ATTR, "Send ChannelData to peer\n");
//  nb = sendto(desc->relayed_sock, msg, len, 0, (struct sockaddr*)&storage,
//      sockaddr_get_size(&desc->relayed_addr));

	boost::asio::const_buffer SendBuff(msg,len);
	udp::endpoint sender_endpoint(boost::asio::ip::address::from_string(buf1), peer_port);
	desc->relayed_socket_ptr->async_send_to(
		boost::asio::buffer(SendBuff), sender_endpoint,
		m_pHandler->get_strand().wrap(
		  boost::bind(&Udp_Handle::handle_send_to, m_pHandler,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred)));

#ifdef OS_SET_DF_SUPPORT
	/* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
	if(optlen)
	{
		/* restore original value */
		setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
				sizeof(int));
	}
#endif

//	if(nb == -1)
// 	{
//		debug(DBG_ATTR, "turn_send_message_asyn failed\n");
// 	}

	return 0;
}

	/**
	 * \brief Process a TURN Send indication.
	 * \param message TURN message
	 * \param desc allocation descriptor
	 * \return 0 if success, -1 otherwise
	 */
int TurnServer::turnserver_process_send_indication(
		const struct turn_message* message, struct allocation_desc* desc)
{
	debug(DBG_ATTR, "Send indication received!\n");

	size_t len = 0;
	int family = 0;
	if(!message->peer_addr[0] || !message->data)
	{
		/* no peer address, indication ignored */
		debug(DBG_ATTR, "No peer address\n");
		return -1;
	}

	switch(message->peer_addr[0]->turn_attr_family)
	{
		case STUN_ATTR_FAMILY_IPV4:
		len = 4;
		family = AF_INET;
		break;
		case STUN_ATTR_FAMILY_IPV6:
		len = 16;
		family = AF_INET6;
		break;
		default:
		return -1;
		break;
	}

	if(desc->relayed_addr.ss_family != family)
	{
		debug(DBG_ATTR, "Could not relayed from a different family\n");
		return -1;
	}

	/* copy peer address */
	uint16_t peer_port = 0;
	uint8_t peer_addr[16] = {0};
	uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
	uint8_t* p = (uint8_t*) &cookie;
	memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
	peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

	if(turn_xor_address_cookie(message->peer_addr[0]->turn_attr_family,peer_addr,
        &peer_port, p, message->msg->turn_msg_id) == -1)
	{
		return -1;
	}

	/* find a permission */
	struct allocation_permission* alloc_permission = NULL;
	alloc_permission = allocation_desc_find_permission(desc,
			desc->relayed_addr.ss_family, peer_addr);

	char str[INET6_ADDRSTRLEN] = {0};
	if(!alloc_permission)
	{
		/* no permission so packet dropped! */
		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
		debug(DBG_ATTR, "No permission for this peer (%s)\n", str);
		return -1;
	}

	/* send the message */
	struct sockaddr_storage storage;
	const char* msg = NULL;
	size_t msg_len = 0;
	if(message->data)
	{
		msg = (char*)message->data->turn_attr_data;
		msg_len = ntohs(message->data->turn_attr_len);

		/* check bandwidth limit */
		if(turnserver_check_bandwidth_limit(desc, 0, msg_len))
		{
		  debug(DBG_ATTR, "Bandwidth quotas reached!\n");
		  return -1;
		}

		switch(desc->relayed_addr.ss_family)
		{
		  case AF_INET:
			((struct sockaddr_in*)&storage)->sin_family = AF_INET;
			memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
			((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
			memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
				sizeof((struct sockaddr_in*)&storage)->sin_zero);
			break;
		  case AF_INET6:
			((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
			((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
			((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
			((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
	#ifdef SIN6_LEN
			((struct sockaddr_in6*)&storage)->sin6_len =
			  sizeof(struct sockaddr_in6);
	#endif
			break;
		  default:
			return -1;
			break;
		}

		/* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
		 * server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
		 */
		/* for get/setsockopt */
		int optval = 0;
		int save_val = 0;
		socklen_t optlen = sizeof(int);
		if(desc->relayed_addr.ss_family == AF_INET &&
				(desc->tuple.client_addr.ss_family == AF_INET ||
						(desc->tuple.client_addr.ss_family == AF_INET6 &&
								IN6_IS_ADDR_V4MAPPED(
										&((struct sockaddr_in6*)&desc->tuple.client_addr)->sin6_addr))))
		{
			/* following is for IPv4-IPv4 relay only */
			#ifdef OS_SET_DF_SUPPORT
				  if(message->dont_fragment)
				  {
					optval = IP_PMTUDISC_DO;
					debug(DBG_ATTR, "Will set DF flag\n");
				  }
				  else /* IPv4-IPv4 relay but no DONT-FRAGMENT attribute */
				  {
					/* alternate behavior, set DF to 0 */
					optval = IP_PMTUDISC_DONT;
					debug(DBG_ATTR, "Will not set DF flag\n");
				  }

				  if(!getsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
						&optlen))
				  {
					setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
						sizeof(int));
				  }
				  else
				  {
					/* little hack for not setting the old value of *_MTU_DISCOVER after
					 * sending message in case getsockopt failed
					 */
					optlen = 0;
				  }
			#else
				  /* avoid compilation warning */
				  optval = 0;
				  optlen = 0;
				  save_val = 0;

				  if(message->dont_fragment)
				  {
					/* ignore message */
					debug(DBG_ATTR, "DONT-FRAGMENT attribute present and OS cannot set DF flag, ignore packet!\n");
					return -1;
				  }
			#endif
		}

		debug(DBG_ATTR, "Send data to peer\n");
//		size_t nb = sendto(desc->relayed_sock, msg, msg_len, 0, (struct sockaddr*)&storage,
//				sockaddr_get_size(&desc->relayed_addr));

		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
		boost::asio::const_buffer SendBuff(msg,msg_len);
		udp::endpoint sender_endpoint(boost::asio::ip::address::from_string(str), peer_port);
		desc->relayed_socket_ptr->async_send_to(
			boost::asio::buffer(SendBuff), sender_endpoint,
			m_pHandler->get_strand().wrap(
			  boost::bind(&Udp_Handle::handle_send_to, m_pHandler,
	          boost::asio::placeholders::error,
	          boost::asio::placeholders::bytes_transferred)));

			/* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
		#ifdef OS_SET_DF_SUPPORT
			if(optlen)
			{
			  /* restore original value */
			  setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
				  sizeof(int));
			}
		#endif

//		if(nb == -1)
//		{
//		  debug(DBG_ATTR, "turn_send_message_asyn failed\n");
//		}
	}

	return 0;
}

	/**
	 * \brief Process a TURN CreatePermission request.
	 * \param transport_protocol transport protocol used
	 * \param sock socket
	 * \param message TURN message
	 * \param saddr source address of the message
	 * \param saddr_size sizeof addr
	 * \param desc allocation descriptor
	 * \param speer TLS peer, if not NULL the connection is in TLS so response is
	 * also in TLS
	 * \return 0 if success, -1 otherwise
	 */
int TurnServer::turnserver_process_createpermission_request(
		int transport_protocol, int sock, const struct turn_message* message,
		const struct sockaddr* saddr, socklen_t saddr_size,
		struct allocation_desc* desc, struct tls_peer* speer)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);

	debug(DBG_ATTR, "CreatePermission request received\n");

	if(message->xor_peer_addr_overflow)
	{
		/* too many XOR-PEER-ADDRESS attributes => error 508 */
		debug(DBG_ATTR, "Too many XOR-PEER-ADDRESS attributes\n");
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 508, saddr, saddr_size, speer, desc->key);
		return -1;
    }

	if(!message->peer_addr[0])
	{
		/* no XOR-PEER-ADDRESS => error 400 */
		debug(DBG_ATTR, "Missing address attribute\n");
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
		return -1;
	}

	/* get string representation of addresses for log */
//	char str3[INET6_ADDRSTRLEN] = {0};
//	uint16_t port = 0;
//	if(desc->relayed_addr.ss_family == AF_INET)
//	{
//		inet_ntop(AF_INET, &((struct sockaddr_in*)&desc->relayed_addr)->sin_addr,
//				str3, INET6_ADDRSTRLEN);
//		port = ntohs(((struct sockaddr_in*)&desc->relayed_addr)->sin_port);
//	}
//	else /* IPv6 */
//	{
//		inet_ntop(AF_INET6, &((struct sockaddr_in6*)&desc->relayed_addr)->sin6_addr,
//				str3, INET6_ADDRSTRLEN);
//		port = ntohs(((struct sockaddr_in6*)&desc->relayed_addr)->sin6_port);
//	}
//
//	char str2[INET6_ADDRSTRLEN] = {0};
//	uint16_t port2 = 0;
//	if(saddr->sa_family == AF_INET)
//	{
//		inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str2,
//				INET6_ADDRSTRLEN);
//		port2 = ntohs(((struct sockaddr_in*)saddr)->sin_port);
//	}
//	else /* IPv6 */
//	{
//		inet_ntop(AF_INET6, &((struct sockaddr_in6*)saddr)->sin6_addr, str2,
//				INET6_ADDRSTRLEN);
//		port2 = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
//	}

	/* check address family for all XOR-PEER-ADDRESS attributes against the
	 * relayed ones
	 */
//	for(size_t i = 0 ; i < XOR_PEER_ADDRESS_MAX && message->peer_addr[i] ; i++)
//	{
//		switch(message->peer_addr[i]->turn_attr_family)
//		{
//			case STUN_ATTR_FAMILY_IPV4:
//				len = 4;
//				family = AF_INET;
//				break;
//			case STUN_ATTR_FAMILY_IPV6:
//				len = 16;
//				family = AF_INET6;
//				break;
//			default:
//				return -1;
//		}
//
//		if((desc->relayed_addr.ss_family != family))
//		{
//			/* peer family mismatch => error 443 */
//			debug(DBG_ATTR, "Peer family mismatch\n");
//			turnserver_send_error(transport_protocol, sock, method,
//					message->msg->turn_msg_id, 443, saddr, saddr_size, speer, desc->key);
//			return -1;
//		}
//
//		/* now check that address is not denied */
//		memcpy(peer_addr, message->peer_addr[i]->turn_attr_address, len);
//		peer_port = ntohs(message->peer_addr[i]->turn_attr_port);
//
//		if(turn_xor_address_cookie(message->peer_addr[i]->turn_attr_family,
//          peer_addr, &peer_port, p, message->msg->turn_msg_id) == -1)
//		{
//			return -1;
//		}
//
//		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
//	}

	uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
	uint8_t* p = (uint8_t*) &cookie;
	uint16_t peer_port = 0;
	uint8_t peer_addr[16] = {0};
	size_t len = 0;
	struct allocation_permission* alloc_permission = NULL;
	char str[INET6_ADDRSTRLEN] = {0};
	int family = 0;
	for(size_t j = 0 ; j < XOR_PEER_ADDRESS_MAX && message->peer_addr[j] ; j++)
	{
		/* copy peer address */
		switch(message->peer_addr[j]->turn_attr_family)
		{
			case STUN_ATTR_FAMILY_IPV4:
				len = 4;
				family = AF_INET;
				break;
			case STUN_ATTR_FAMILY_IPV6:
				len = 16;
				family = AF_INET6;
				break;
			default:
				return -1;
		}

		memcpy(peer_addr, message->peer_addr[j]->turn_attr_address, len);
		peer_port = ntohs(message->peer_addr[j]->turn_attr_port);

		if(turn_xor_address_cookie(message->peer_addr[j]->turn_attr_family,
			  peer_addr, &peer_port, p, message->msg->turn_msg_id) == -1)
		{
		  return -1;
		}

		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);

		/* find a permission */
		alloc_permission = allocation_desc_find_permission(desc,
			desc->relayed_addr.ss_family, peer_addr);

		/* update or create allocation permission on that peer */
		if(!alloc_permission)
		{
			debug(DBG_ATTR, "Install permission for %s %u\n", str, peer_port);
				allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME,
						desc->relayed_addr.ss_family, peer_addr);
		}
		else
		{
			debug(DBG_ATTR, "Refresh permission\n");
			allocation_permission_set_timer(alloc_permission, TURN_DEFAULT_PERMISSION_LIFETIME);
		}
	}

	/* send a CreatePermission success response */
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct iovec iov[4]; /* header, software, integrity, fingerprint */
	size_t idx = 0;
	if(!(hdr = turn_msg_createpermission_response_create(0,
          message->msg->turn_msg_id, &iov[idx])))
	{
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
		return -1;
	}
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
	== -1)
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
		return -1;
	}

	debug(DBG_ATTR, "CreatePermission successful, send success CreatePermission response\n");

  /* finally send the response */
	if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
        == -1)
	{
		debug(DBG_ATTR, "turn_send_message_asyn failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}

	/**
	 * \brief Process a TURN ChannelBind request.
	 * \param transport_protocol transport protocol used
	 * \param sock socket
	 * \param message TURN message
	 * \param saddr source address of the message
	 * \param saddr_size sizeof addr
	 * \param desc allocation descriptor
	 * \param speer TLS peer, if not NULL the connection is in TLS so response is
	 * also in TLS
	 * \return 0 if success, -1 otherwise
	 */
int TurnServer::turnserver_process_channelbind_request(int transport_protocol,
		int sock, const struct turn_message* message,
		const struct sockaddr* saddr, socklen_t saddr_size,
		struct allocation_desc* desc, struct tls_peer* speer)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);

	debug(DBG_ATTR, "ChannelBind request received!\n");

	if(!message->channel_number || !message->peer_addr[0])
	{
		/* attributes missing => error 400 */
		debug(DBG_ATTR, "Channel number or peer address attributes missing\n");
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
		return 0;
	}

	uint16_t channel = ntohs(message->channel_number->turn_attr_number);
	if(channel < 0x4000 || channel > 0x7FFF)
	{
		/* bad channel => error 400 */
		debug(DBG_ATTR, "Channel number is invalid\n");
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
		return 0;
	}

	uint8_t family = 0;
	size_t len = 0;
	switch(message->peer_addr[0]->turn_attr_family)
	{
		case STUN_ATTR_FAMILY_IPV4:
		  len = 4;
		  family = AF_INET;
		  break;
		case STUN_ATTR_FAMILY_IPV6:
		  len = 16;
		  family = AF_INET6;
		  break;
		default:
		  return -1;
		  break;
	}

	/* check if the client has allocated a family address that match the peer
	* family address
	*/
	if(desc->relayed_addr.ss_family != family)
	{
		debug(DBG_ATTR, "Do not allow requesting a Channel when allocated address "
				"family mismatch peer address family\n");
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 443, saddr, saddr_size, speer, desc->key);
		return -1;
	}

	uint16_t peer_port = 0;
	uint8_t peer_addr[16] = {0};
	memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
	peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

	uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
	uint8_t* p = (uint8_t*) &cookie;
	if(turn_xor_address_cookie(message->peer_addr[0]->turn_attr_family, peer_addr,
		&peer_port, p, message->msg->turn_msg_id) == -1)
	{
		return -1;
	}

	char str[INET6_ADDRSTRLEN] = {0};
	inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);

	debug(DBG_ATTR, "Client request a ChannelBinding for %s %u\n", str, peer_port);

  /* check that the transport address is not currently bound to another
   * channel
   */
	uint32_t channel_use = 0; /* if refresh an existing ChannelBind */
	channel_use = allocation_desc_find_channel(desc, family, peer_addr, peer_port);
	if(channel_use && channel_use != channel)
	{
		/* transport address already bound to another channel */
		debug(DBG_ATTR, "Transport address already bound to another channel\n");
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
		return 0;
	}

	struct allocation_channel* alloc_channel = allocation_desc_find_channel_number(desc, channel);
	if(alloc_channel)
	{
		/* check if same transport address */
		if(alloc_channel->peer_port != peer_port ||
				memcmp(alloc_channel->peer_addr, peer_addr, len) != 0)
		{
			/* different transport address => error 400 */
			debug(DBG_ATTR, "Channel already bound to another transport address\n");
			turnserver_send_error(transport_protocol, sock, method,
					message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
			return 0;
		}
		/* same transport address OK so refresh */
		allocation_channel_set_timer(alloc_channel, TURN_DEFAULT_CHANNEL_LIFETIME);
	}
    else
    {
    	/* allocate new channel */
    	if(allocation_desc_add_channel(desc, channel, TURN_DEFAULT_CHANNEL_LIFETIME,
    			family, peer_addr, peer_port) == -1)
    	{
    		return -1;
    	}
    }

//	char str2[INET6_ADDRSTRLEN] = {0};
//	char str3[INET6_ADDRSTRLEN] = {0};
//	uint16_t port = 0;
//	uint16_t port2 = 0;
//	/* get string representation of addresses for log */
//	if(desc->relayed_addr.ss_family == AF_INET)
//	{
//		inet_ntop(AF_INET, &((struct sockaddr_in*)&desc->relayed_addr)->sin_addr,
//				str3, INET6_ADDRSTRLEN);
//		port = ntohs(((struct sockaddr_in*)&desc->relayed_addr)->sin_port);
//	}
//	else /* IPv6 */
//	{
//		inet_ntop(AF_INET6, &((struct sockaddr_in6*)&desc->relayed_addr)->sin6_addr,
//				str3, INET6_ADDRSTRLEN);
//		port = ntohs(((struct sockaddr_in6*)&desc->relayed_addr)->sin6_port);
//	}
//
//	if(saddr->sa_family == AF_INET)
//	{
//		inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str2,
//				INET6_ADDRSTRLEN);
//		port2 = ntohs(((struct sockaddr_in*)saddr)->sin_port);
//	}
//	else /* IPv6 */
//	{
//		inet_ntop(AF_INET6, &((struct sockaddr_in6*)saddr)->sin6_addr, str2,
//				INET6_ADDRSTRLEN);
//		port2 = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
//	}

	/* find a permission */
	struct allocation_permission* alloc_permission = allocation_desc_find_permission(desc, family, peer_addr);

	/* update or create allocation permission on that peer */
	if(!alloc_permission)
	{
		allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME,
				family, peer_addr);
	}
	else
	{
		allocation_permission_set_timer(alloc_permission,
				TURN_DEFAULT_PERMISSION_LIFETIME);
	}

	/* finally send the response */
	struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
	size_t idx = 0;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	if(!(hdr = turn_msg_channelbind_response_create(0, message->msg->turn_msg_id,
          &iov[idx])))
	{
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
		return -1;
 	}
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		  sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
	  == -1)
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
		return -1;
	}

		debug(DBG_ATTR,
				"ChannelBind successful, send success ChannelBind response\n");

	/* finally send the response */
	if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
	  == -1)
	{
		debug(DBG_ATTR, "turn_send_message_asyn failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}

	/**
	 * \brief Process a TURN Refresh request.
	 * \param transport_protocol transport protocol used
	 * \param sock socket
	 * \param message TURN message
	 * \param saddr source address of the message
	 * \param saddr_size sizeof addr
	 * \param allocation_list list of allocations
	 * \param desc allocation descriptor
	 * \param account account descriptor
	 * \param speer TLS peer, if not NULL the connection is in TLS so response is
	 * also in TLS
	 * \return 0 if success, -1 otherwise
	 */
int TurnServer::turnserver_process_refresh_request(int transport_protocol,
		int sock, const struct turn_message* message,
		const struct sockaddr* saddr, socklen_t saddr_size,
		struct list_head* allocation_list, struct allocation_desc* desc,
		struct account_desc* account, struct tls_peer* speer)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	uint32_t lifetime = 0;
	struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
	size_t idx = 0;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;

	debug(DBG_ATTR, "Refresh request received!\n");

	/* save key from allocation as it could be freed if lifetime equals 0 */
	uint8_t key[16] = {0};
	memcpy(key, desc->key, sizeof(desc->key));

	/* if REQUESTED-ADDRESS-FAMILY attribute is present and do not match relayed
	 * address ones => error 443
	 */
	if(message->requested_addr_family)
	{
		int family = 0;

		switch(message->requested_addr_family->turn_attr_family)
		{
			case STUN_ATTR_FAMILY_IPV4:
			family = AF_INET;
			break;
			case STUN_ATTR_FAMILY_IPV6:
			family = AF_INET6;
			break;
			default:
			return -1;
		}

		if(desc->relayed_addr.ss_family != family)
		{
			/* peer family mismatch => error 443 */
			debug(DBG_ATTR, "Peer family mismatch\n");
			turnserver_send_error(transport_protocol, sock, method,
					message->msg->turn_msg_id, 443, saddr, saddr_size, speer,key);
			return -1;
		}
	}

	if(message->lifetime)
	{
		lifetime = htonl(message->lifetime->turn_attr_lifetime);

		debug(DBG_ATTR, "lifetime: %u seconds\n", lifetime);

		/* adjust lifetime (cannot be greater that maximum allowed) */
		lifetime = MIN(lifetime, TURN_MAX_ALLOCATION_LIFETIME);

		if(lifetime > 0)
		{
			/* lifetime cannot be smaller than default */
			lifetime = MAX(lifetime, TURN_DEFAULT_ALLOCATION_LIFETIME);
  	 }
	}
	else
	{
		/* cannot override default max value for allocation time */
		lifetime = MIN(Singleton_IConfig->m_life_time,  TURN_DEFAULT_ALLOCATION_LIFETIME);
	}

	char str[INET6_ADDRSTRLEN] = {0};
	uint16_t port = 0;
	if(saddr->sa_family == AF_INET)
	{
		inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str,
				INET6_ADDRSTRLEN);
		port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
	}
	else /* IPv6 */
	{
		inet_ntop(AF_INET6, &((struct sockaddr_in6*)saddr)->sin6_addr, str,
				INET6_ADDRSTRLEN);
		port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
	}

	if(lifetime > 0)
	{
		/* adjust lifetime */
		debug(DBG_ATTR, "Refresh allocation\n");
		allocation_desc_set_timer(desc, lifetime);
	}
	else
	{
		/* lifetime = 0 delete the allocation */
		/* protect the removing of the expired list if any */
		turnserver_block_realtime_signal();
		allocation_desc_set_timer(desc, 0); /* stop timeout */
		/* in case the allocation has expired during this statement */
		LIST_DEL(&desc->list2);
		turnserver_unblock_realtime_signal();

		allocation_list_remove(allocation_list, desc);

		/* decrement allocations for the account */
		account->allocations--;
		debug(DBG_ATTR, "Account %s, allocations used: %u\n", account->username,
				account->allocations);
		debug(DBG_ATTR, "Explicit delete of allocation\n");
		if(account->allocations == 0 && account->is_tmp)
		{
		  account_list_remove(NULL, account);
		}
	}

	if(!(hdr = turn_msg_refresh_response_create(0, message->msg->turn_msg_id, &iov[idx])))
	{
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, speer, key);
		return -1;
	}
	idx++;

	if(!(attr = turn_attr_lifetime_create(lifetime, &iov[idx])))
	{
	iovec_free_data(iov, idx);
	turnserver_send_error(transport_protocol, sock, method,
		message->msg->turn_msg_id, 500, saddr, saddr_size, speer, key);
	return -1;
	}
	hdr->turn_msg_len += iov[idx].iov_len;
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		  sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
	hdr->turn_msg_len += iov[idx].iov_len;
	idx++;
	}

	if(turn_add_message_integrity(iov, &idx, key, sizeof(key), 1) == -1)
	{
	iovec_free_data(iov, idx);
	turnserver_send_error(transport_protocol, sock, method,
		message->msg->turn_msg_id, 500, saddr, saddr_size, speer, key);
	return -1;
	}

	debug(DBG_ATTR, "Refresh successful, send success refresh response\n");

	/* finally send the response */
	if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
	  == -1)
	{
	debug(DBG_ATTR, "turn_send_message_asyn failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}

	/**
	 * \brief Process a TURN Allocate request.
	 * \param transport_protocol transport protocol used
	 * \param sock socket
	 * \param message TURN message
	 * \param saddr source address of the message
	 * \param daddr destination address of the message
	 * \param saddr_size sizeof addr
	 * \param allocation_list list of allocations
	 * \param account account descriptor
	 * \param speer TLS peer, if not NULL the connection is in TLS so response is
	 * also in TLS
	 * \return 0 if success, -1 otherwise
	 */
int TurnServer::turnserver_process_allocate_request(int transport_protocol,
		int sock, const struct turn_message* message,
		const struct sockaddr* saddr, const struct sockaddr* daddr,
		socklen_t saddr_size, struct list_head* allocation_list,
		struct account_desc* account, struct tls_peer* speer)
{
	debug(DBG_ATTR, "Allocate request received!\n");

	struct itimerspec t; /* time before expire */
	uint16_t hdr_msg_type = ntohs(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	struct sockaddr_storage relayed_addr;
	int r_flag = 0;
	uint32_t lifetime = 0;
	uint16_t port = 0;
	uint16_t reservation_port = 0;
	int relayed_sock = -1;
	udp::socket* relayed_socket_ptr = NULL;
	int relayed_sock_tcp = -1; /* RFC6062 (TURN-TCP) */
	int reservation_sock = -1;
	socklen_t relayed_size = sizeof(struct sockaddr_storage);
	size_t quit_loop = 0;
	uint8_t reservation_token[8];
	char str[INET6_ADDRSTRLEN];
	char str2[INET6_ADDRSTRLEN];
	uint16_t port2 = 0;
	int has_token = 0;
	char* family_address = NULL;
	const uint16_t max_port = Singleton_IConfig->m_max_port;
	const uint16_t min_port = Singleton_IConfig->m_min_port;

	/* check if it was a valid allocation */
	struct allocation_desc* desc = allocation_list_find_tuple(allocation_list, transport_protocol, daddr,
			saddr, saddr_size);
	if(desc)
	{
		if(transport_protocol == IPPROTO_UDP && !memcmp(message->msg->turn_msg_id,
				desc->transaction_id, 12))
		{
			// the request is a retransmission of a valid request, rebuild the response
			/* get some states */
			timer_gettime(desc->expire_timer, &t);
			lifetime = t.it_value.tv_sec;
			memcpy(&relayed_addr, &desc->relayed_addr, sizeof(struct sockaddr_storage));
			/* goto is bad... */
			goto send_success_response;
		}
		else
		{
			/* allocation mismatch => error 437 */
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 437, saddr, saddr_size, speer, desc->key);
		}

		return 0;
	}

	/* get string representation of address for syslog */
	if(saddr->sa_family == AF_INET)
	{
		inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str2,
				INET6_ADDRSTRLEN);
		port2 = ntohs(((struct sockaddr_in*)saddr)->sin_port);
	}

	/* check for allocation quota */
	if(account->allocations >= Singleton_IConfig->m_max_relay_per_username)
	{
		/* quota exceeded => error 486 */
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 486, saddr, saddr_size, speer, account->key);
		return -1;
	}

	/* check requested-transport */
	if(!message->requested_transport) //UDP
	{
		/* bad request => error 400 */
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
		return 0;
	}

  /* check if DONT-FRAGMENT attribute is supported */
#ifndef OS_SET_DF_SUPPORT
	if(message->dont_fragment)
	{
		/* header, error-code, unknown-attributes, software, message-integrity,
		 * fingerprint
		 */
		struct iovec iov[6];
		uint16_t unknown[2];
		struct turn_msg_hdr* error = NULL;
		struct turn_attr_hdr* attr = NULL;
		size_t idx = 0;

		/* send error 420 */
		unknown[0] = TURN_ATTR_DONT_FRAGMENT;

		if(!(error = turn_error_response_420(method, message->msg->turn_msg_id,
				unknown, 1, iov, &idx)))
		{
		  turnserver_send_error(transport_protocol, sock, method,
			  message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
			  account->key);
		  return -1;
		}

		/* software (not fatal if it cannot be allocated) */
		if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
				sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
		{
		  error->turn_msg_len += iov[idx].iov_len;
		  idx++;
		}

		if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
			== -1)
		{
		  iovec_free_data(iov, idx);
		  turnserver_send_error(transport_protocol, sock, method,
			  message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
			  account->key);
		  return -1;
		}

		if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
			  ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
			== -1)
		{
		  debug(DBG_ATTR, "turn_send_message_asyn failed\n");
		}

		/* free sent data */
		iovec_free_data(iov, idx);
		return 0;
	}
#endif

	if(message->even_port && message->reservation_token)
	{
		/* cannot have both EVEN-PORT and RESERVATION-TOKEN => error 400 */
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
		return 0;
	}

	if(message->requested_addr_family && message->reservation_token)
	{
		/* RFC6156: cannot have both REQUESTED-ADDRESS-FAMILY and RESERVATION-TOKEN
		 * => error 400
		 */
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
		return 0;
	}

    /* check reservation-token */
    if(message->reservation_token) //此时在allocation请求中，直接使用token保存的地址作为relay address
    {
    	struct allocation_token* token = NULL;

    	/* check if the requested reservation-token exists */
    	if((token = allocation_token_list_find(&g_token_list,
    			message->reservation_token->turn_attr_token)))
    	{
    		relayed_sock = token->sock;
    		has_token = 1;

    		/* suppress from the list */
    		turnserver_block_realtime_signal();
    		allocation_token_set_timer(token, 0); /* stop timer */
    		LIST_DEL(&token->list2);
    		turnserver_unblock_realtime_signal();

    		allocation_token_list_remove(&g_token_list, token);
    		debug(DBG_ATTR, "Take token reserved address!\n");
    	}
    	else
    	{
    		/* token does not exists so token not valid => error 508 */
    		turnserver_send_error(transport_protocol, sock, method,
    				message->msg->turn_msg_id, 508, saddr, saddr_size, speer,
    				account->key);
    		return 0;
    	}
    }

    if(message->even_port) //是否保留下一个更高的端口号
    {
    	r_flag = message->even_port->turn_attr_flags & 0x80;

    	/* check if there are unknown other flags */
    	if(message->even_port->turn_attr_flags & (~g_supported_even_port_flags))
    	{
    		/* unsupported flags => error 508 */
    		turnserver_send_error(transport_protocol, sock, method,
    			message->msg->turn_msg_id, 508, saddr, saddr_size, speer,
    			account->key);
    		return 0;
    	}
    }

    if(message->lifetime)
    {
    	lifetime = htonl(message->lifetime->turn_attr_lifetime);

    	debug(DBG_ATTR, "lifetime: %u seconds\n", lifetime);

    	/* adjust lifetime (cannot be greater than maximum allowed) */
    	lifetime = MIN(lifetime, TURN_MAX_ALLOCATION_LIFETIME);

    	/* lifetime cannot be smaller than default */
    	lifetime = MAX(lifetime, TURN_DEFAULT_ALLOCATION_LIFETIME);
    }
    else
    {
    	/* cannot override default max value for allocation time */
    	lifetime = MIN(Singleton_IConfig->m_life_time, TURN_MAX_ALLOCATION_LIFETIME);
    }

    /* RFC6156 */
    if(message->requested_addr_family) //ipv4 or ipv6 默认采用ipv4
    {
    	switch(message->requested_addr_family->turn_attr_family)
    	{
			case STUN_ATTR_FAMILY_IPV4:
				family_address = Singleton_IConfig->m_MediaSrv_lanIp.c_str();//192.168.15.250
				break;
			case STUN_ATTR_FAMILY_IPV6:
				family_address = "::";
				break;
			default:
				family_address = NULL;
				break;
    	}
		/* check the family requested is supported */
		if(!family_address)
		{
			/* family not supported */
			turnserver_send_error(transport_protocol, sock, method,
			  message->msg->turn_msg_id, 440, saddr, saddr_size, speer,
			  account->key);
			return -1;
		}
    }
    else
    {
    	/* REQUESTED-ADDRESS-FAMILY absent so allocate an IPv4 address */
    	family_address = Singleton_IConfig->m_MediaSrv_lanIp.c_str();//"192.168.15.250"; //turnserver_cfg_listen_address();

		if(!family_address)
		{
			/* only happen when IPv4 relaying is disabled and try to allocate IPv6
			* address without adding REQUESTED-ADDRESS-FAMILY attribute.
			*/
			/* family not supported */
			turnserver_send_error(transport_protocol, sock, method,
			  message->msg->turn_msg_id, 440, saddr, saddr_size, speer,
			  account->key);
			return -1;
		}
    }

    strncpy(str, family_address, INET6_ADDRSTRLEN);
    str[INET6_ADDRSTRLEN - 1] = 0x00;

    /* after all these checks, allocate an allocation!
     * allocate the relayed address or skip this if server has a token,
     * try 5 times to find a free port or couple of free ports.
     */
    while(!has_token && (relayed_sock == -1 && quit_loop < 5))
    {
		/* pick up a port (default between 49152 - 65535) */
		port = (uint16_t) (rand() % (max_port - min_port)) + min_port;

		/* allocate a even port */
		if(message->even_port && (port % 2))
		{
			port++;
		}

		relayed_socket_ptr = new udp::socket(m_pHandler->get_ios(),udp::endpoint(boost::asio::ip::address::from_string(str), port));
//    	relayed_sock = socket_create(
//        message->requested_transport->turn_attr_protocol, str, port,
//        message->requested_transport->turn_attr_protocol == IPPROTO_TCP,
//        message->requested_transport->turn_attr_protocol == IPPROTO_TCP);

		if(relayed_socket_ptr == NULL)
		{
			quit_loop++;
			continue;
		}
		boost::asio::socket_base::send_buffer_size sendoption(Singleton_IConfig->m_BuffSize);
		relayed_socket_ptr->set_option(sendoption);
		boost::asio::socket_base::receive_buffer_size recvoption(Singleton_IConfig->m_BuffSize);
		relayed_socket_ptr->set_option(recvoption);
		relayed_sock = relayed_socket_ptr->native();

		if(relayed_sock == -1)
		{
		  quit_loop++;
		  continue;
		}

		if(r_flag) //创建一个预留的socket
		{
			reservation_port = port + 1;
			reservation_sock = socket_create(UDP, str, reservation_port, 0, 0);

			if(reservation_sock == -1)
			{
				close(relayed_sock);
				relayed_sock = -1;
			}
			else
			{
				struct allocation_token* token = NULL;

				/* store the reservation */
				random_bytes_generate(reservation_token, 8);

				token = allocation_token_new(reservation_token, reservation_sock, TURN_DEFAULT_TOKEN_LIFETIME);
				if(token)
				{
					allocation_token_list_add(&g_token_list, token);
				}
				else
				{
					close(reservation_sock);
//					close(relayed_sock);
					relayed_socket_ptr->close();
					reservation_sock = -1;
					relayed_sock = -1;
				}
			}
		}

		quit_loop++;
    }

    if(relayed_sock == -1)
    {
    	char error_str[256];
    	get_error(errno, error_str, sizeof(error_str));
    	debug(DBG_ATTR, "Unable to allocate socket: %s\n", error_str);
    	turnserver_send_error(transport_protocol, sock, method,
    			message->msg->turn_msg_id, 500, saddr, saddr_size, speer, account->key);
    	return -1;
    }

	if(getsockname(relayed_sock, (struct sockaddr*)&relayed_addr, &relayed_size)
	  != 0)
	{
		char error_str[256];
		get_error(errno, error_str, sizeof(error_str));
		syslog(LOG_ERR, "Error in getsockname: %s", error_str);
		close(relayed_sock);
		return -1;
	}

	if(relayed_addr.ss_family == AF_INET)
	{
		port = ntohs(((struct sockaddr_in*)&relayed_addr)->sin_port);
	}
	else /* IPv6 */
	{
		port = ntohs(((struct sockaddr_in6*)&relayed_addr)->sin6_port);
	}

	desc = allocation_desc_new(message->msg->turn_msg_id, transport_protocol,
      account->username, account->key, account->realm,
      message->nonce->turn_attr_nonce, (struct sockaddr*)&relayed_addr, daddr,
      saddr, sizeof(struct sockaddr_storage), lifetime);

	if(!desc)
	{
		/* send error response with code 500 */
		turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, speer, account->key);
		close(relayed_sock);
		return -1;
	}

	/* init token bucket */
	if(account->state == AUTHORIZED)
	{
		/* store it in bytes */
		desc->bucket_capacity = Singleton_IConfig->m_bandwidth_per_allocation * 1000;
	}
	else
	{
		/* store it in bytes */
		desc->bucket_capacity = Singleton_IConfig->m_restricted_bandwidth * 1000;
	}

	desc->bucket_tokenup = desc->bucket_capacity;
	desc->bucket_tokendown = desc->bucket_capacity;

	desc->relayed_transport_protocol = message->requested_transport->turn_attr_protocol;

	/* increment number of allocations */
	account->allocations++;
	debug(DBG_ATTR, "Account %s, allocations used: %u\n", account->username, account->allocations);

	/* assign the sockets to the allocation */
    desc->relayed_sock = relayed_sock;
	desc->relayed_socket_ptr = relayed_socket_ptr;
    desc->tuple_sock = sock;

    /* add to the list */
    allocation_list_add(allocation_list, desc);

  /* send back the success response */
send_success_response:
  {
    /* header, relayed-address, lifetime, reservation-token (if any),
     * xor-mapped-address, username, software, message-integrity, fingerprint
     */
    struct iovec iov[12];
    struct turn_msg_hdr* hdr = NULL;
    struct turn_attr_hdr* attr = NULL;
    size_t idx = 0;

    if(!(hdr = turn_msg_allocate_response_create(0, message->msg->turn_msg_id, &iov[idx])))
    {
    	turnserver_send_error(transport_protocol, sock, method,
    		message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    	return -1;
    }
    idx++;

    /* required attributes */
    if(!(attr = turn_attr_xor_relayed_address_create(
            (struct sockaddr*)&relayed_addr, STUN_MAGIC_COOKIE,
            message->msg->turn_msg_id, &iov[idx])))
    {
    	iovec_free_data(iov, idx);
    	turnserver_send_error(transport_protocol, sock, method,
    		message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    	return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    if(!(attr = turn_attr_lifetime_create(lifetime, &iov[idx])))
    {
    	iovec_free_data(iov, idx);
    	turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500,saddr, saddr_size, speer, desc->key);
    	return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    switch(saddr->sa_family)
    {
      case AF_INET:
        port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
        break;
      case AF_INET6:
        port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
        break;
      default:
        iovec_free_data(iov, idx);
        return -1;
        break;
    }

    if(!(attr = turn_attr_xor_mapped_address_create(saddr, STUN_MAGIC_COOKIE,
            message->msg->turn_msg_id, &iov[idx])))
    {
    	iovec_free_data(iov, idx);
    	turnserver_send_error(transport_protocol, sock, method,
    			message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    	return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    if(reservation_port)
    {
    	/* server has stored a socket/port */
    	debug(DBG_ATTR, "Send a reservation-token attribute\n");
    	if(!(attr = turn_attr_reservation_token_create(reservation_token,
              &iov[idx])))
    	{
    		iovec_free_data(iov, idx);
    		turnserver_send_error(transport_protocol, sock, method,
    				message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
    				desc->key);
    		return -1;
    	}
    	hdr->turn_msg_len += iov[idx].iov_len;
    	idx++;
    }

    /* software (not fatal if it cannot be allocated) */
    if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
            sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
    {
    	hdr->turn_msg_len += iov[idx].iov_len;
    	idx++;
    }

    if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
        == -1)
    {
    	iovec_free_data(iov, idx);
    	turnserver_send_error(transport_protocol, sock, method,
    			message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    	return -1;
    }

    debug(DBG_ATTR, "Allocation successful, send success allocate response\n");

    if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
          ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
        == -1)
    {
    	debug(DBG_ATTR, "turn_send_message_asyn failed\n");
    }

		iovec_free_data(iov, idx);
  }

  return 0;
}

	/**
	 * \brief Process a TURN request.
	 * \param transport_protocol transport protocol used
	 * \param sock socket
	 * \param message TURN message
	 * \param saddr source address of the message
	 * \param daddr destination address of the message
	 * \param saddr_size sizeof addr
	 * \param allocation_list list of allocations
	 * \param account account descriptor (may be NULL)
	 * \param speer TLS peer, if not NULL the connection is in TLS so response is
	 * also in TLS
	 * \return 0 if success, -1 otherwise
	 */
int TurnServer::turnserver_process_turn(int transport_protocol, int sock,
		const struct turn_message* message, const struct sockaddr* saddr,
		const struct sockaddr* daddr, socklen_t saddr_size,
		struct list_head* allocation_list, struct account_desc* account,
		struct tls_peer* speer)
{
	uint16_t hdr_msg_type = 0;
	uint16_t method = 0;
	struct allocation_desc* desc = NULL;

	hdr_msg_type = ntohs(message->msg->turn_msg_type);
	method = STUN_GET_METHOD(hdr_msg_type);
	debug(DBG_ATTR, "Process a TURN message: method = 0x%x \n",method);

	// process STUN binding request
	if(STUN_IS_REQUEST(hdr_msg_type) && method == STUN_METHOD_BINDING)
	{
		return turnserver_process_binding_request(transport_protocol, sock, message,
				saddr, saddr_size, speer);
    }

	/* check the 5-tuple except for an Allocate request */
	if(method != TURN_METHOD_ALLOCATE)
	{
        char buf1[128] = {0};
		inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, buf1, 128);
		int port1 = ntohs(((struct sockaddr_in*)saddr)->sin_port);
		char buf2[128] = {0};
		inet_ntop(AF_INET, &((struct sockaddr_in*)daddr)->sin_addr, buf2, 128);
		int port2 = ntohs(((struct sockaddr_in*)daddr)->sin_port);
		debug(DBG_ATTR, "find tuple for saddr_ip = %s, saddr_port = %d, daddr_ip = %s, daddr_port = %d\n",buf1, port1, buf2, port2 );

		desc = allocation_list_find_tuple(allocation_list, transport_protocol,  daddr, saddr, saddr_size);

		if(STUN_IS_REQUEST(hdr_msg_type))
		{
			/* check for the allocated username */
			if(desc && message->username && message->realm)
			{
				size_t len = ntohs(message->username->turn_attr_len);
				size_t rlen = ntohs(message->realm->turn_attr_len);
				if(len != strlen(desc->username) || strncmp((char*)message->username->turn_attr_username,
						desc->username, len) || rlen != strlen(desc->realm) ||
						strncmp((char*)message->realm->turn_attr_realm, desc->realm, rlen))
				{
					desc = NULL;
				}
			}
			else
			{
				desc = NULL;
			}
		}

		if(!desc)
		{
			/* reject with error 437 if it a request, ignored otherwise */
			/* the refresh function will handle this case */
			if(STUN_IS_REQUEST(hdr_msg_type))
			{
				/* allocation mismatch => error 437 */
				turnserver_send_error(transport_protocol, sock, method,
						message->msg->turn_msg_id, 437, saddr, saddr_size, speer,
						account->key);
				return 0;
			}

			debug(DBG_ATTR, "No valid 5-tuple match\n");
			return -1;
		}

		/* update allocation nonce */
		if(message->nonce)
		{
			memcpy(desc->nonce, message->nonce->turn_attr_nonce, 24);
		}
	}

	if(STUN_IS_REQUEST(hdr_msg_type)) //处理请求
	{
		if(method != TURN_METHOD_ALLOCATE)
		{
			/* check to prevent hijacking the client's allocation */
			size_t len = strlen(account->username);
			size_t rlen = strlen(account->realm);
			if(len != ntohs(message->username->turn_attr_len) ||
					strncmp((char*)message->username->turn_attr_username,
					account->username, len) ||
					rlen != ntohs(message->realm->turn_attr_len) ||
					strncmp((char*)message->realm->turn_attr_realm, account->realm, rlen))
			{
				/* credentials do not match with those used for allocation
				 * => error 441
				 */
				debug(DBG_ATTR, "Wrong credentials!\n");
				turnserver_send_error(transport_protocol, sock, method,
					message->msg->turn_msg_id, 441, saddr, saddr_size, speer,
					account->key);
				return 0;
			}
		}

		switch(method)
		{
			case TURN_METHOD_ALLOCATE:
			turnserver_process_allocate_request(transport_protocol, sock, message,
				saddr, daddr, saddr_size, allocation_list, account, speer);
			PrintAllocationList();
			break;
			case TURN_METHOD_REFRESH:
			turnserver_process_refresh_request(transport_protocol, sock, message,
				saddr, saddr_size, allocation_list, desc, account, speer);
			break;
			case TURN_METHOD_CREATEPERMISSION:
			turnserver_process_createpermission_request(transport_protocol, sock,
				message, saddr, saddr_size, desc, speer);
			break;
			case TURN_METHOD_CHANNELBIND:
			/* ChannelBind is only for UDP relay */
			if(desc->relayed_transport_protocol == IPPROTO_UDP)
			{
			  turnserver_process_channelbind_request(transport_protocol, sock,
				  message, saddr, saddr_size, desc, speer);
			}
			else
			{
			  turnserver_send_error(transport_protocol, sock, method,
				  message->msg->turn_msg_id, 400, saddr, saddr_size, speer,
				  desc->key);
			}
			break;
			case TURN_METHOD_CONNECT: /* RFC6062 (TURN-TCP) */
			/* Connect is only for TCP or TLS over TCP <-> TCP */
			if(transport_protocol == IPPROTO_TCP &&
				desc->relayed_transport_protocol == IPPROTO_TCP)
			{
			//          turnserver_process_connect_request(transport_protocol, sock, message,
			//              saddr, saddr_size, desc, speer);
			}
			else
			{
			  turnserver_send_error(transport_protocol, sock, method,
				  message->msg->turn_msg_id, 400, saddr, saddr_size, speer,
				  desc->key);
			}
			break;
			default:
			return -1;
			break;
		}
	}
	else if(STUN_IS_SUCCESS_RESP(hdr_msg_type) || STUN_IS_ERROR_RESP(hdr_msg_type))
	{
		/* should not happen */
	}
	else if(STUN_IS_INDICATION(hdr_msg_type))  //处理indication
	{
		switch(method)
		{
		  case TURN_METHOD_SEND:
			if(desc->relayed_transport_protocol == IPPROTO_UDP)
			{
			  turnserver_process_send_indication(message, desc);
			}
			break;
		  case TURN_METHOD_DATA:
			/* should not happen */
			return -1;
			break;
		}
	}
	return 0;
}

int TurnServer::turnserver_listen_recv(int transport_protocol, int sock,
		const char* buf, ssize_t buflen, const struct sockaddr* saddr,
		const struct sockaddr* daddr, socklen_t saddr_size,
		struct list_head* allocation_list, struct list_head* account_list,
		struct tls_peer* speer)
{
	struct account_desc* account = NULL;
	uint16_t method = 0;

	/* protocol mismatch */
	if (transport_protocol != IPPROTO_UDP)
	{
		debug(DBG_ATTR, "Transport protocol mismatch\n");
		return -1;
	}
	if(buflen < 4)
	{
		debug(DBG_ATTR, "Size too short\n");
		return -1;
	}
	//获取消息类型
	uint16_t type = 0;
	memcpy(&type, buf, sizeof(uint16_t));
	type = ntohs(type);
	// is it a ChannelData message (bit 0 and 1 are not set to 0) ?
	if(TURN_IS_CHANNELDATA(type))
	{
		/* ChannelData 为数据消息，直接进行转发*/
		return turnserver_process_channeldata(transport_protocol,type, buf, buflen,
				saddr, daddr, saddr_size, allocation_list);
    }

	uint16_t unknown[32];
	size_t unknown_size = sizeof(unknown) / sizeof(uint32_t); //最大解析的unknow attribute数量
	struct turn_message message;
	//将buf中的所有属性值解析出来，放入message中
	if(turn_parse_message(buf, buflen, &message, unknown, &unknown_size) == -1)
	{
		debug(DBG_ATTR, "Parse message failed\n");
		return -1;
	}

	if(!message.msg)
	{
		debug(DBG_ATTR, "No STUN/TURN header\n");
		return -1;
	}

	uint16_t hdr_msg_type = ntohs(message.msg->turn_msg_type);
	size_t total_len = ntohs(message.msg->turn_msg_len) + sizeof(struct turn_msg_hdr);

	// 检查消息种类
	if(!STUN_IS_REQUEST(hdr_msg_type) && !STUN_IS_INDICATION(hdr_msg_type) &&
	   !STUN_IS_SUCCESS_RESP(hdr_msg_type) && !STUN_IS_ERROR_RESP(hdr_msg_type))
	{
		debug(DBG_ATTR, "Unknown message class\n");
		return -1;
	}
	//获取消息类型
	method = STUN_GET_METHOD(hdr_msg_type);

	/* check that the method value is supported */
	if(method != STUN_METHOD_BINDING &&
	 method != TURN_METHOD_ALLOCATE &&
	 method != TURN_METHOD_REFRESH &&
	 method != TURN_METHOD_CREATEPERMISSION &&
	 method != TURN_METHOD_CHANNELBIND &&
	 method != TURN_METHOD_SEND &&
	 method != TURN_METHOD_DATA
	//     (method != TURN_METHOD_CONNECT || !turn_tcp) &&
	//     (method != TURN_METHOD_CONNECTIONBIND || !turn_tcp))
	 )
	{
		debug(DBG_ATTR, "Unknown method\n");
		return -1;
	}

	// check the magic cookie
	if(message.msg->turn_msg_cookie != htonl(STUN_MAGIC_COOKIE))
	{
		debug(DBG_ATTR, "Bad magic cookie\n");
		return -1;
	}

	// check the fingerprint if present
	if(message.fingerprint)
	{
		uint32_t crc = crc32_generate((const unsigned char*)buf,
				total_len - sizeof(struct turn_attr_fingerprint), 0);

		if(htonl(crc) != (message.fingerprint->turn_attr_crc ^ htonl(STUN_FINGERPRINT_XOR_VALUE)))
		{
			debug(DBG_ATTR, "Fingerprint mismatch\n");
			return -1;
		}
	}

	// all this cases above discard silently the packets, so now process the packet more in details,安全校验
	if(STUN_IS_REQUEST(hdr_msg_type) && method != STUN_METHOD_BINDING)
	{
		// check long-term authentication for all requests except for a STUN  binding request
		if(!message.message_integrity)
		{
			// no messages integrity => error 401
			// header, error-code, realm, nonce, software
			struct iovec iov[12] = {0};
			size_t idx = 0;
			uint8_t nonce[48] = {0};

			struct turn_attr_hdr* attr = NULL;

			debug(DBG_ATTR, "No message integrity\n");

			char* key = Singleton_IConfig->m_nonce_key.c_str(); //"hieKedq";
			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key, strlen(key));

			struct turn_msg_hdr* error = NULL;
			if(!(error = turn_error_response_401(method, message.msg->turn_msg_id,
				  Singleton_IConfig->m_realm.c_str(), nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method,
						message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
				return -1;
			}

			// software (not fatal if it cannot be allocated)
			if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
				  sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
				error->turn_msg_len += iov[idx].iov_len;
				idx++;
			}

			turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

			error->turn_msg_len = htons(error->turn_msg_len);

			if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
				ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
				idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message_asyn failed\n");
			}

			// free sent data
			iovec_free_data(iov, idx);
			return 0;
		}

		if(!message.username || !message.realm || !message.nonce)
		{
			// missing username, realm or nonce => error 400
			turnserver_send_error(transport_protocol, sock, method,
					message.msg->turn_msg_id, 400, saddr, saddr_size, speer, NULL);
			return 0;
		}

		//检查nonce是否过期
		if(turn_nonce_is_stale(message.nonce->turn_attr_nonce,
			ntohs(message.nonce->turn_attr_len),
			(unsigned char*)Singleton_IConfig->m_nonce_key.c_str(),
			strlen("hieKedq")))
		{
			// nonce staled => error 438
			// header, error-code, realm, nonce, software
			struct iovec iov[5];
			size_t idx = 0;
			struct turn_msg_hdr* error = NULL;
			struct turn_attr_hdr* attr = NULL;
			uint8_t nonce[48];
			char* realm = Singleton_IConfig->m_realm.c_str();
			char* key = Singleton_IConfig->m_nonce_key.c_str();

			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key, strlen(key));
			idx = 0;

			if(!(error = turn_error_response_438(method, message.msg->turn_msg_id,
				  realm, nonce, sizeof(nonce), iov, &idx)))
			{
			  turnserver_send_error(transport_protocol, sock, method,
				message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
			  return -1;
			}

			/* software (not fatal if it cannot be allocated) */
			if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
				  sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
			  error->turn_msg_len += iov[idx].iov_len;
			  idx++;
			}

			/* convert to big endian */
			error->turn_msg_len = htons(error->turn_msg_len);

			if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
				ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
				idx) == -1)
			{
			debug(DBG_ATTR, "turn_send_message_asyn failed\n");
			}

			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}

    // find the desired username and password in the account list

		size_t username_len = ntohs(message.username->turn_attr_len) + 1;
		size_t realm_len = ntohs(message.realm->turn_attr_len) + 1;

		if(username_len > 513 || realm_len > 256)
		{
			/* some attributes are too long */
			turnserver_send_error(transport_protocol, sock, method,
					message.msg->turn_msg_id, 400, saddr, saddr_size, speer, NULL);
			return -1;
		}

		char username[514] = {0};
		strncpy(username, (char*)message.username->turn_attr_username, username_len);
		username[username_len - 1] = 0x00;
		char user_realm[256] = {0};
		strncpy(user_realm, (char*)message.realm->turn_attr_realm, realm_len);
		user_realm[realm_len - 1] = 0x00;

		// search the account
		account = account_list_find(account_list, username, user_realm);

		if(!account)
		{
			// not valid username => error 401
			struct iovec iov[5];     // header, error-code, realm, nonce, software
			size_t idx = 0;
			char* realm = "demo"; //turnserver_cfg_realm();
			char* key = "hieKedq"; //turnserver_cfg_nonce_key();

			debug(DBG_ATTR, "No account\n");

			uint8_t nonce[48] = {0};
			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key, strlen(key));

			idx = 0;
			struct turn_msg_hdr* error = NULL;
			if(!(error = turn_error_response_401(method, message.msg->turn_msg_id,
					realm, nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method,
						message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
				return -1;
			}

			struct turn_attr_hdr* attr = NULL;
			/* software (not fatal if it cannot be allocated) */
			if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
					sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
				error->turn_msg_len += iov[idx].iov_len;
				idx++;
			}

			turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

			/* convert to big endian */
			error->turn_msg_len = htons(error->turn_msg_len);

			if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
				  ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
				  idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message_asyn failed\n");
			}

			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}

		//假如账户存在
		/* compute HMAC-SHA1 and compare with the value in message_integrity */
		uint8_t hash[20];
        if(message.fingerprint) //去掉integrity和fingerprint后计算哈希值
        {
        	/* if the message contains a FINGERPRINT attribute, adjust the size */
        	size_t len_save = message.msg->turn_msg_len;

        	message.msg->turn_msg_len = ntohs(message.msg->turn_msg_len) -
        			sizeof(struct turn_attr_fingerprint);

        	message.msg->turn_msg_len = htons(message.msg->turn_msg_len);
				turn_calculate_integrity_hmac((const unsigned char*)buf,
						total_len - sizeof(struct turn_attr_fingerprint) -
						sizeof(struct turn_attr_message_integrity), account->key,
						sizeof(account->key), hash);

        	/* restore length */
        	message.msg->turn_msg_len = len_save;
        }
        else //去掉integrity后计算哈希值
        {
        	turn_calculate_integrity_hmac((const unsigned char*)buf,
        			total_len - sizeof(struct turn_attr_message_integrity),
        			account->key, sizeof(account->key), hash);
        }

        if(memcmp(hash, message.message_integrity->turn_attr_hmac, 20) != 0) //哈希值校验失败
        {
			/* integrity does not match => error 401 */
			struct iovec iov[5]; /* header, error-code, realm, nonce, software */
			size_t idx = 0;
			struct turn_msg_hdr* error = NULL;
			struct turn_attr_hdr* attr = NULL;
			uint8_t nonce[48];
			char* nonce_key = "hieKedq"; //turnserver_cfg_nonce_key();

			debug(DBG_ATTR, "Hash mismatch\n");
			#ifndef NDEBUG
			/* print computed hash and the one from the message */
			digest_print(hash, 20);
			digest_print(message.message_integrity->turn_attr_hmac, 20);
			#endif
			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));

			idx = 0;

			if(!(error = turn_error_response_401(method, message.msg->turn_msg_id,
                /*turnserver_cfg_realm()*/"demo", nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method,
						message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
				return -1;
			}

			/* software (not fatal if it cannot be allocated) */
			if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
					sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
			  error->turn_msg_len += iov[idx].iov_len;
			  idx++;
			}

			turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

			/* convert to big endian */
			error->turn_msg_len = htons(error->turn_msg_len);

			if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
				  ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
				  idx) == -1)
			{
			  debug(DBG_ATTR, "turn_send_message_asyn failed\n");
			}

			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
        }
	}

	/* check if there are unknown comprehension-required attributes */
	if(unknown_size)
	{
		// if not a request, message is discarded
		if(!STUN_IS_REQUEST(hdr_msg_type))
		{
			debug(DBG_ATTR, "message has unknown attribute and it is not a request, discard\n");
			return -1;
		}
	    struct iovec iov[4]; /* header, error-code, unknown-attributes, software */
	    size_t idx = 0;
	    struct turn_msg_hdr* error = NULL;
		/* unknown attributes found => error 420 */
		if(!(error = turn_error_response_420(method, message.msg->turn_msg_id,
				unknown, unknown_size, iov, &idx)))
		{
			turnserver_send_error(transport_protocol, sock, method,
					message.msg->turn_msg_id, 500, saddr, saddr_size, speer,
					account ? account->key : NULL);
			return -1;
		}

		struct turn_attr_hdr* attr = NULL;
		/* software (not fatal if it cannot be allocated) */
		if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
				sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
		{
			error->turn_msg_len += iov[idx].iov_len;
			idx++;
		}

		/* convert to big endian */
		error->turn_msg_len = htons(error->turn_msg_len);

		if(turn_send_message_asyn(transport_protocol, sock, speer, saddr, saddr_size,
			  ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
			== -1)
		{
		  debug(DBG_ATTR, "turn_send_message_asyn failed\n");
		}

		/* free sent data */
		iovec_free_data(iov, idx);
		return 0;
	}

	// the basic checks are done, now check that specific method requirement are OK
	debug(DBG_ATTR, "OK basic validation are done, process the TURN message\n");

	return turnserver_process_turn(transport_protocol, sock, &message, saddr,
			daddr, saddr_size, allocation_list, account, speer);
}

		/**
		 * \brief Receive a message on an relayed address.
		 * \param buf data received
		 * \param buflen length of data
		 * \param saddr source address of the message
		 * \param daddr destination address of the message
		 * \param saddr_size sizeof addr
		 * \param allocation_list list of allocations
		 * \param speer TLS peer, if not NULL, message is relayed in TLS
		 * \return 0 if message processed correctly, -1 otherwise
		 */
int TurnServer::turnserver_relayed_recv(const char* buf, ssize_t buflen,
		const struct sockaddr* saddr, struct sockaddr* daddr,
		socklen_t saddr_size, struct list_head* allocation_list,
		struct tls_peer* speer) {
	struct allocation_desc* desc = NULL;
	uint8_t peer_addr[16];
	uint16_t peer_port;
	uint32_t channel = 0;
	struct iovec iov[8]; /* header, peer-address, data */
	size_t idx = 0;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct turn_channel_data channel_data;
	uint32_t padding = 0;
	ssize_t nb = -1;
	size_t len = 0; /* for TLS */
	char str[INET6_ADDRSTRLEN];

	char buf10[INET6_ADDRSTRLEN] = { 0 };
	memset(buf10, 0, sizeof(buf10));
	inet_ntop(AF_INET, &((struct sockaddr_in*) saddr)->sin_addr, buf10,
			INET6_ADDRSTRLEN);
	int port10 = ntohs((((struct sockaddr_in*) saddr)->sin_port));

	char buf11[INET6_ADDRSTRLEN] = { 0 };
	memset(buf11, 0, sizeof(buf11));
	inet_ntop(AF_INET, &(((struct sockaddr_in*) daddr)->sin_addr), buf11,
			INET6_ADDRSTRLEN);
	int port11 = ntohs((((struct sockaddr_in*) daddr)->sin_port));

	debug(DBG_ATTR, "saddr_ip = %s, saddr_port = %d, daddr_ip = %s, daddr_port = %d\n",buf10, port10, buf11, port11);

	/* find the allocation associated with the relayed transport address */
	desc = allocation_list_find_relayed(allocation_list, daddr, saddr_size);
	if(!desc)
	{
		/* no allocation found, discard */
		debug(DBG_ATTR, "No allocation found\n");
		return -1;
	}

	switch(saddr->sa_family)
	{
		case AF_INET:
		memcpy(peer_addr, &((struct sockaddr_in*)saddr)->sin_addr, 4);
		peer_port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
		break;
		case AF_INET6:
		memcpy(peer_addr, &((struct sockaddr_in6*)saddr)->sin6_addr, 16);
		peer_port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
		break;
		default:
		return -1;
	}

	/* check if the peer has permission */
	if(!allocation_desc_find_permission_sockaddr(desc, saddr))
	{
		/* no permission, discard */
		inet_ntop(saddr->sa_family, peer_addr, str, INET6_ADDRSTRLEN);
		debug(DBG_ATTR, "No permission installed (%s)\n", str);
		return -1;
	}

	/* check bandwidth limit */
	if(turnserver_check_bandwidth_limit(desc, buflen, 0))
	{
		debug(DBG_ATTR, "Bandwidth quotas reached!\n");
		return -1;
	}

	/* see if a channel is bound to the peer */
	channel = allocation_desc_find_channel(desc, saddr->sa_family, peer_addr,
			peer_port);

	if(channel != 0)
	{
		len = sizeof(struct turn_channel_data);

		/* send it with ChannelData */
		channel_data.turn_channel_number = htons(channel);
		channel_data.turn_channel_len = htons(buflen); /* big endian */

		iov[idx].iov_base = &channel_data;
		iov[idx].iov_len = sizeof(struct turn_channel_data);
		idx++;

		if(buflen > 0)
		{
			iov[idx].iov_base = (void*)buf;
			iov[idx].iov_len = buflen;
			len += buflen;
			idx++;
		}

		/* add padding (MUST be included for TCP, MAY be included for UDP) */
		if(buflen % 4)
		{
			iov[idx].iov_base = &padding;
			iov[idx].iov_len = 4 - (buflen % 4);
			len += iov[idx].iov_len;
			idx++;
		}
	}
	else
	{
		/* send it with Data Indication */
		uint8_t id[12];

		turn_generate_transaction_id(id);
		if(!(hdr = turn_msg_data_indication_create(0, id, &iov[idx])))
    {
      return -1;
    }
    idx++;

    if(!(attr = turn_attr_xor_peer_address_create(saddr, STUN_MAGIC_COOKIE, id,
            &iov[idx])))
    {
      iovec_free_data(iov, idx);
      return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    if(!(attr = turn_attr_data_create(buf, buflen, &iov[idx])))
    {
      iovec_free_data(iov, idx);
      return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    len = hdr->turn_msg_len + sizeof(struct turn_msg_hdr);
    hdr->turn_msg_len = htons(hdr->turn_msg_len);
  }

  /* send it to the tuple (TURN client) */
  debug(DBG_ATTR, "Send data to client\n");

  if(desc->tuple.transport_protocol == IPPROTO_UDP) /* UDP */
  {
    int optval = 0;
    int save_val = 0;
    socklen_t optlen = sizeof(int);

#ifdef OS_SET_DF_SUPPORT
    /* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
     * server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
     */
    if((desc->tuple.client_addr.ss_family == AF_INET ||
          (desc->tuple.client_addr.ss_family == AF_INET6 &&
           IN6_IS_ADDR_V4MAPPED(
             &((struct sockaddr_in6*)&desc->tuple.client_addr)->sin6_addr))) &&
       (saddr->sa_family == AF_INET || (saddr->sa_family == AF_INET6 &&
       IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)saddr)->sin6_addr))))
    {
      /* only for IPv4-IPv4 relay */
      /* alternate behavior, set DF to 0 */
      optval = IP_PMTUDISC_DONT;

      if(!getsockopt(desc->tuple_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
            &optlen))
      {
        setsockopt(desc->tuple_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
            sizeof(int));
      }
      else
      {
        /* little hack for not setting the old value of *_MTU_DISCOVER after
         * sending message in case getsockopt failed
         */
        optlen = 0;
      }
    }
#else
    optlen = 0;
    optval = 0;
    save_val = 0;
#endif

    nb = turn_udp_send(desc->tuple_sock,
        (struct sockaddr*)&desc->tuple.client_addr,
        sockaddr_get_size(&desc->tuple.client_addr), iov, idx);

    turn_send_message_asyn(IPPROTO_UDP, desc->tuple_sock, NULL, (struct sockaddr*)&desc->tuple.client_addr,
    		sockaddr_get_size(&desc->tuple.client_addr), len, iov, idx);

//	boost::asio::const_buffer SendBuff(msg,len);
//	udp::endpoint sender_endpoint(boost::asio::ip::address::from_string(buf1), peer_port);
//	desc->relayed_socket_ptr->async_send_to(
//		boost::asio::buffer(SendBuff), sender_endpoint,
//		m_pHandler->get_strand().wrap(
//		  boost::bind(&Udp_Handle::handle_send_to, m_pHandler,
//          boost::asio::placeholders::error,
//          boost::asio::placeholders::bytes_transferred)));

    /* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
#ifdef OS_SET_DF_SUPPORT
    if(optlen)
    {
      /* restore original value */
      setsockopt(desc->tuple_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
          sizeof(int));
    }
#endif
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_send_message_asyn failed\n");
  }

  /* if use a channel, do not used dynamic allocation */
  if(!channel)
  {
    iovec_free_data(iov, idx);
  }

  return 0;
}

	/**
	 * \brief Check if server can relay specific address with its current
	 * configuration.
	 *
	 * For example if IPv6 is disabled, the server will drop immediately packets
	 * coming from an IPv6-only client.
	 * \param listen_address IPv4 listen address
	 * \param listen_addressv6 IPv6 listen_address (could be NULL if IPv6 is
	 * disabled)
	 * \param saddr source address of client
	 * \return 1 if the server can relay data for this client,
	 * 0 otherwise
	 */
static int turnserver_check_relay_address(char* listen_address,
		char* listen_addressv6, struct sockaddr_storage* saddr) {
	if ((!listen_addressv6
			&& (saddr->ss_family == AF_INET6
					&& !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)saddr)->sin6_addr)))
			|| (!listen_address
					&& (saddr->ss_family == AF_INET6
							&& IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)saddr)->sin6_addr)))
			|| (!listen_address && saddr->ss_family == AF_INET)) {
		return 0;
	}

	return 1;
}

void TurnServer::handler_receive_client(unsigned char * data, unsigned int len,
		std::string SourceAddr, unsigned int SourcePort)
{
    debug(DBG_ATTR, "Received UDP on listening address: ip = %s, port = %d\n", SourceAddr.c_str(), SourcePort);
	char* proto = NULL;
	char* listen_address = Singleton_IConfig->m_MediaSrv_lanIp.c_str();//"192.168.15.250";
	char* listen_addressv6 = "::";
	sockaddr_storage saddr, daddr;
	socklen_t saddr_size = sizeof(struct sockaddr_storage);

	((sockaddr_in*)&saddr)->sin_family = AF_INET;
	((sockaddr_in*)&saddr)->sin_addr.s_addr = inet_addr(SourceAddr.c_str());
	((sockaddr_in*)&saddr)->sin_port = htons(SourcePort);
	memset(((sockaddr_in*)&saddr)->sin_zero, 0, sizeof(((sockaddr_in*)&saddr)->sin_zero));

//	getsockname(GetSocket(), (struct sockaddr*)&daddr, &daddr_size);
	((sockaddr_in*)&daddr)->sin_family = AF_INET;
	((sockaddr_in*)&daddr)->sin_addr.s_addr = inet_addr(Singleton_IConfig->m_MediaSrv_lanIp.c_str());
	((sockaddr_in*)&daddr)->sin_port = htons(Singleton_IConfig->m_MediaPort);
	memset(((sockaddr_in*)&daddr)->sin_zero, 0, sizeof(((sockaddr_in*)&saddr)->sin_zero));

	if(!turnserver_check_relay_address(listen_address, listen_addressv6, &saddr))
	{
		proto = (saddr.ss_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))
				? "IPv6" : "IPv4";
		debug(DBG_ATTR, "Do not relay family: %s\n", proto);
	}
	else if(turnserver_listen_recv(IPPROTO_UDP, m_pHandler->get_socket(), data, len,
			(struct sockaddr*)&saddr, (struct sockaddr*)&daddr,
			saddr_size, &allocation_list, &account_list, NULL) == -1)
	{
	  debug(DBG_ATTR, "Bad STUN/TURN message or permission problem\n");
	}
}

void TurnServer::handler_receive_relay(unsigned char * data, unsigned int len,
		std::string SourceAddr, unsigned int SourcePort, int peer_relay_socket) {
	/* relayed UDP-based addresses */
	/* UDP relay is described in RFC 5766*/

	debug(DBG_ATTR, "Received UDP on a relayed address\n");
	sockaddr_storage saddr, daddr;
	socklen_t saddr_size = sizeof(struct sockaddr_storage);
	socklen_t daddr_size = sizeof(struct sockaddr_storage);

	((sockaddr_in*)&saddr)->sin_family = AF_INET;
	((sockaddr_in*)&saddr)->sin_addr.s_addr = inet_addr(SourceAddr.c_str());
	((sockaddr_in*)&saddr)->sin_port = htons(SourcePort);
	memset(((sockaddr_in*)&saddr)->sin_zero, 0, sizeof(((sockaddr_in*)&saddr)->sin_zero));

	getsockname(peer_relay_socket, (struct sockaddr*)&daddr, &daddr_size);

	  if(len > 0)
	  {
		turnserver_relayed_recv(data, len, (struct sockaddr*)&saddr,
			(struct sockaddr*)&daddr, saddr_size, &allocation_list, NULL);
	  }
	  else
	  {
//		get_error(errno, error_str, sizeof(error_str));
	  }

}

	//void handler_receive_client111(unsigned char * data,unsigned int len,std::string SourceAddr,unsigned int SourcePort)
	//{
	//  struct list_head* n = NULL;
	//  struct list_head* get = NULL;
	//  struct timespec tv;
	//  int nsock = -1;
	//  char error_str[1024];
	//  sigset_t mask;
	//  char buf[8192];
	//  struct sockaddr_storage saddr;
	//  socklen_t saddr_size = sizeof(struct sockaddr_storage);
	//  struct sockaddr_storage daddr;
	//  socklen_t daddr_size = sizeof(struct sockaddr_storage);
	//
	//  char* proto = NULL;
	//  char* listen_address = "192.168.15.250"; //turnserver_cfg_listen_address();
	//  char* listen_addressv6 = ""; //turnserver_cfg_listen_addressv6();
	//
	//  (void)proto;
	//
	//    /* main UDP listen socket */
	//	 if(SourcePort == 9100)
	//    {
	//        debug(DBG_ATTR, "Received UDP on listening address\n");
	//        saddr_size = sizeof(struct sockaddr_storage);
	//        daddr_size = sizeof(struct sockaddr_storage);
	//
	//		if(!turnserver_check_relay_address(listen_address, listen_addressv6,
	//			  &saddr))
	//		{
	//		  proto = (saddr.ss_family == AF_INET6 &&
	//			  !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))
	//			? "IPv6" : "IPv4";
	//		  debug(DBG_ATTR, "Do not relay family: %s\n", proto);
	//		}
	//		else if(turnserver_listen_recv(IPPROTO_UDP, m_pHandler->get_socket(), buf, nb,
	//				(struct sockaddr*)&saddr, (struct sockaddr*)&daddr,
	//				saddr_size, allocation_list, account_list, NULL) == -1)
	//		{
	//		  debug(DBG_ATTR, "Bad STUN/TURN message or permission problem\n");
	//		}
	//    }
	//	else
	//	{
	//		/* relayed UDP-based addresses */
	//		list_iterate_safe(get, n, allocation_list)
	//		{
	//		  struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
	//		  struct list_head* get2 = NULL;
	//		  struct list_head* n2 = NULL;
	//
	//		  /* relayed address */
	//		  if(sfd_has_data(tmp->relayed_sock, max_fd, &fdsr))
	//		  {
	//			/* UDP relay is described in RFC 5766*/
	//			if(tmp->relayed_transport_protocol == IPPROTO_UDP)
	//			{
	//			  debug(DBG_ATTR, "Received UDP on a relayed address\n");
	//			  saddr_size = sizeof(struct sockaddr_storage);
	//			  daddr_size = sizeof(struct sockaddr_storage);
	//
	//			  getsockname(tmp->relayed_sock, (struct sockaddr*)&daddr, &daddr_size);
	//			  nb = recvfrom(tmp->relayed_sock, buf, sizeof(buf), 0,
	//				  (struct sockaddr*)&saddr, &saddr_size);
	//
	//	//          char buf1[INET6_ADDRSTRLEN] = {};
	//	//          inet_ntop(AF_INET, &(((struct sockaddr_in*)&saddr)->sin_addr), buf1, INET6_ADDRSTRLEN);
	//	//          int port1 = ntohs(((struct sockaddr_in*)&saddr)->sin_port);
	//	//          char buf2[INET6_ADDRSTRLEN] = {};
	//	//          inet_ntop(AF_INET, &(((struct sockaddr_in*)&daddr)->sin_addr), buf1, INET6_ADDRSTRLEN);
	//	//          int port2 = ntohs(((struct sockaddr_in*)&daddr)->sin_port);
	//	//		  debug(DBG_ATTR, "saddr_ip = %s, saddr_port = %d, daddr_ip = %s, daddr_port = %d\n", buf1, port1, buf2, port2);
	//
	//			  if(nb > 0)
	//			  {
	//				turnserver_relayed_recv(buf, nb, (struct sockaddr*)&saddr,
	//					(struct sockaddr*)&daddr, saddr_size, allocation_list, NULL);
	//			  }
	//			  else
	//			  {
	//				get_error(errno, error_str, sizeof(error_str));
	//			  }
	//			}
	//		  }
	//		}
	//
	//	  }
	//
	//}

	/**
	 * \brief Cleanup function used when fork() to correctly free() ressources.
	 * \param arg argument, in this case it is the account_list pointer
	 */
void TurnServer::turnserver_cleanup(void* arg) {
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	/* account_list */
	list_head* accounts = arg;

	/* configuration file */
	//  turnserver_cfg_free();

	if (accounts) {
		account_list_free(accounts);
	}
}

/**
 * \brief Write pid in a file.
 * \param pidfile pidfile pathname
 */
static void turnserver_write_pidfile(const char *pidfile) {
	if (pidfile) {
		FILE *f = fopen(pidfile, "w");

		if (!f) {
			syslog(LOG_ERR, "Can't open %s for write: %s", pidfile, strerror(
					errno));
		} else {
			fprintf(f, "%d\n", getpid());
			fclose(f);
		}
	}
}

/**
 * \brief Remove pidfile.
 * \param pidfile pidfile pathname
 */
static void turnserver_remove_pidfile(const char* pidfile) {
	if (pidfile) {
		unlink(pidfile);
	}
}

void TurnServer::init_turnserver_data_list() {
	//		g_reinit = 0;
	g_run = 0;
	/* initialize lists */
	INIT_LIST(allocation_list);
	INIT_LIST(account_list);
	INIT_LIST(g_token_list);

	/* initialize expired lists */
	INIT_LIST(g_expired_allocation_list);
	INIT_LIST(g_expired_permission_list);
	INIT_LIST(g_expired_channel_list);
	INIT_LIST(g_expired_token_list);

	/* initialize sockets */
	sockets.sock_udp = -1;
	sockets.sock_tcp = -1;
	sockets.sock_tls = NULL;
	sockets.sock_dtls = NULL;
}

void TurnServer::set_signal_handler() {
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	/* catch signals that usealy stop application
	 * without performing cleanup such as SIGINT
	 * (i.e CTRL-C break) and SIGTERM
	 * (i.e kill -TERM command)
	 */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(DBG_ATTR, "SIGINT will not be catched\n");
	}

	if(sigaction(SIGTERM, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGTERM will not be catched\n");
	}

	if(sigaction(SIGPIPE, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGPIPE will not be catched\n");
	}

	/* catch SIGHUP to reload credentials */
	if(sigaction(SIGHUP, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGHUP will not be catched\n");
	}

	/* catch SIGUSR1 and SIGUSR2 to avoid being killed
	 * if someone send these signals
	 */
	if(sigaction(SIGUSR1, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGUSR1 will not be catched\n");
	}

	if(sigaction(SIGUSR2, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGUSR2 will not be catched\n");
	}

	/* realtime handler */
	sa.sa_handler = NULL;
	sa.sa_sigaction = realtime_signal_handler;
	sa.sa_flags = SA_SIGINFO;

	/* as TurnServer uses these signals for expiration
	 * stuff, exit if they cannot be handled by signal handler
	 */
	if(sigaction(SIGRT_EXPIRE_ALLOCATION, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGRT_EXPIRE_ALLOCATION will not be catched\n");
		exit(EXIT_FAILURE);
	}

	if(sigaction(SIGRT_EXPIRE_PERMISSION, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGRT_EXPIRE_PERMISSION will not be catched\n");
		exit(EXIT_FAILURE);
	}

	if(sigaction(SIGRT_EXPIRE_CHANNEL, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGRT_EXPIRE_CHANNEL will not be catched\n");
		exit(EXIT_FAILURE);
	}

	if(sigaction(SIGRT_EXPIRE_TOKEN, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGRT_EXPIRE_TOKEN will not be catched\n");
		exit(EXIT_FAILURE);
	}

	if(sigaction(SIGRT_EXPIRE_TCP_RELAY, &sa, NULL) == -1)
	{
		debug(DBG_ATTR, "SIGRT_EXPIRE_TCP_RELAY will not be catched\n");
		exit(EXIT_FAILURE);
	}
}

void TurnServer::deal_expire_thing() {
	struct list_head* get = NULL;
	struct list_head* n = NULL;
	/* purge lists if needed */
	if (g_expired_allocation_list.next) {
		list_iterate_safe(get, n, &g_expired_allocation_list) {
			struct allocation_desc* tmp = list_get(get, struct allocation_desc,
					list2);

			/* find the account and decrement allocations */
			struct account_desc* desc = account_list_find(&account_list,
					tmp->username, tmp->realm);
			if (desc) {
				desc->allocations--;
				debug(DBG_ATTR, "Account %s, allocations used: %u\n", desc->username,
				desc->allocations);

				/* in case it is a temporary account remove it */
				if(desc->allocations == 0 && desc->is_tmp)
				{
					account_list_remove(&account_list, desc);
				}
			}

			/* remove it from the list of valid allocations */
			debug(DBG_ATTR, "Free an allocation_desc\n");
			LIST_DEL(&tmp->list);
			LIST_DEL(&tmp->list2);
			allocation_desc_free(&tmp);
		}
	}

	if(g_expired_permission_list.next)
	{
		list_iterate_safe(get, n, &g_expired_permission_list)
		{
			struct allocation_permission* tmp =
			list_get(get, struct allocation_permission, list2);

			/* remove it from the list of valid permissions */
			LIST_DEL(&tmp->list);
			LIST_DEL(&tmp->list2);
			debug(DBG_ATTR, "Free an allocation_permission\n");
			timer_delete(tmp->expire_timer);
			free(tmp);
		}
	}

	if(g_expired_channel_list.next)
	{
		list_iterate_safe(get, n, &g_expired_channel_list)
		{
			struct allocation_channel* tmp =
			list_get(get, struct allocation_channel, list2);

			/* remove it from the list of valid channels */
			LIST_DEL(&tmp->list);
			LIST_DEL(&tmp->list2);
			debug(DBG_ATTR, "Free an allocation_channel\n");
			timer_delete(tmp->expire_timer);
			free(tmp);
		}
	}

	if(g_expired_token_list.next)
	{
		list_iterate_safe(get, n, &g_expired_token_list)
		{
			struct allocation_token* tmp =
			list_get(get, struct allocation_token, list2);

			/* remove it from the list of valid tokens */
			LIST_DEL(&tmp->list);
			LIST_DEL(&tmp->list2);
			debug(DBG_ATTR, "Free an allocation_token\n");
			if(tmp->sock > 0)
			{
				close(tmp->sock);
			}
			allocation_token_free(&tmp);
		}
	}
}

bool TurnServer::init_turnserver() {
	allocation_list_tmp = &allocation_list; //用作调试，查看创建的allocation

	struct list_head* n = NULL;
	struct list_head* get = NULL;
	const char* listen_addr = NULL;

	init_turnserver_data_list();

	//读取用户信息
	if (account_parse_file(&account_list, "etc/turnusers.txt") == -1) //configure_path
	{
		fprintf(stderr, "Failed to parse account file, exiting...\n");
		turnserver_cleanup(NULL);
		exit(EXIT_FAILURE);
	}
	list_iterate_safe(get, n, &account_list) {
		struct account_desc* tmp = list_get(get, struct account_desc, list);
		printf("%s %s\n", tmp->username, tmp->realm);
	}

	//	  listen_addr = "0.0.0.0"; //turnserver_cfg_listen_addressv6() ? "::" : "0.0.0.0";
	//
	//	  sockets.sock_udp = socket_create(UDP, listen_addr,
	//	      9100/*turnserver_cfg_udp_port()*/, 0, 0);
	//
	//	  if(sockets.sock_udp == -1)
	//	  {
	//	    debug(DBG_ATTR, "UDP socket creation failed\n");
	//	    g_run = 0;
	//	   // exit(EXIT_FAILURE);
	//	  }
	//	  else
	//	  {
	//	    g_run = 1;
	//	  }

	/* initialize rand() */
	srand(time(NULL) + getpid());

	/* drop privileges if program runs as root */
	if (geteuid() == 0 && uid_drop_privileges(getuid(), getgid(), geteuid(),
			getegid(), "turnserver"/*turnserver_cfg_unpriv_user()*/) == -1) {
		debug(DBG_ATTR, "Cannot drop privileges\n");
	}
	g_run = 1;
	debug(DBG_ATTR,"TurnServer init successful, Run with uid_real=%u gid_real=%u uid_eff=%u gid_eff=%u\n",
	      getuid(), getgid(), geteuid(), getegid());
	  return true;
}

int TurnServer::turnserver_expire() {
	//  init_turnserver();
	if (g_run) {
		//    if(!g_run)
		//    {
		//      break;
		//    }
		/* avoid signal handling during purge */
		turnserver_block_realtime_signal();

		deal_expire_thing();

		/* re-enable realtime signal */
		turnserver_unblock_realtime_signal();

		/* wait messages and processing */
		//    turnserver_main(&sockets, NULL, &allocation_list,
		//        &account_list);
	} else {
		fprintf(stderr, "\n");
		debug(DBG_ATTR, "Exiting, TurnServer stop....\n");

		/* avoid signal handling during cleanup */
		turnserver_block_realtime_signal();

		struct list_head* get = NULL;
		struct list_head* n = NULL;
		/* free the expired allocation list (warning: special version use ->list2) */
		list_iterate_safe(get, n, &g_expired_allocation_list)
		{
			struct allocation_desc* tmp = list_get(get, struct allocation_desc, list2);

			/* note: don't care about decrementing account, after all program exits */
			LIST_DEL(&tmp->list);
			LIST_DEL(&tmp->list2);
			allocation_desc_free(&tmp);
		}

		list_iterate_safe(get, n, &g_expired_token_list)
		{
			struct allocation_token* tmp =
			list_get(get, struct allocation_token, list2);
			LIST_DEL(&tmp->list);
			LIST_DEL(&tmp->list2);
			if(tmp->sock > 0)
			{
				close(tmp->sock);
			}
			allocation_token_free(&tmp);
		}

		/* close UDP and TCP sockets */
		if(sockets.sock_udp > 0)
		{
			close(sockets.sock_udp);
		}

		/* free the valid allocation list */
		allocation_list_free(&allocation_list);

		/* free the account list */
		account_list_free(&account_list);

		/* free the token list */
		allocation_token_list_free(&g_token_list);

		//  if(turnserver_cfg_daemon())
		//  {
		//    turnserver_remove_pidfile(pid_file);
		//  }

		return EXIT_SUCCESS;
	}
}

int TurnServer::turn_send_message_asyn(int transport_protocol, int sock, struct tls_peer* speer,
		const struct sockaddr* addr, socklen_t addr_size, size_t total_len,
		const struct iovec* iov, size_t iovlen)
{
	size_t total_len_cur = 0;
	for(size_t i=0; i<iovlen; i++)
	{
		total_len_cur += iov[i].iov_len;
	}
	if(total_len_cur !=  total_len)
	{
		return -1;
	}
	char* buf = new char[total_len];
	if(NULL == buf)
	{
		return -2;
	}
	int iov_len = 0;
	for(size_t i=0; i<iovlen; i++)
	{
		memcpy(buf + iov_len, iov[i].iov_base, iov[i].iov_len);
		iov_len += iov[i].iov_len;
	}
	char buf1[128] = {0};
	inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, buf1, sizeof(buf1));
	int port = ntohs(((struct sockaddr_in*)addr)->sin_port);
	m_pHandler->handle_async_write(buf, total_len, buf1, port);
	return 0;
}

void PrintAllocationList() {
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	struct list_head* list = allocation_list_tmp;

	list_iterate_safe(get, n, list) {
		struct allocation_desc* tmp =
				list_get(get, struct allocation_desc, list);

		char buf1[INET6_ADDRSTRLEN] = { };
		inet_ntop(AF_INET,
				&((struct sockaddr_in*) &(tmp->tuple.client_addr))->sin_addr,
				buf1, INET6_ADDRSTRLEN);

		char buf2[INET6_ADDRSTRLEN] = { };
		inet_ntop(AF_INET,
				&((struct sockaddr_in*) &(tmp->tuple.server_addr))->sin_addr,
				buf2, INET6_ADDRSTRLEN);

		char buf3[INET6_ADDRSTRLEN] = { };
		inet_ntop(AF_INET,
				&((struct sockaddr_in*) &(tmp->relayed_addr))->sin_addr, buf3,
				INET6_ADDRSTRLEN);

		printf(
				"tuple_transport = %d, client_addr = %s, client_port = %d, server_addr = %s, server_port = %d, relay_transport = %d,  relay_addr = %s, relay_port = %d \n",
				tmp->tuple.transport_protocol,
				buf1,
				ntohs(
						((struct sockaddr_in*) (struct sockaddr*) &(tmp->tuple.client_addr))->sin_port),
				buf2,
				ntohs(
						((struct sockaddr_in*) (struct sockaddr*) &(tmp->tuple.server_addr))->sin_port),
				tmp->tuple.transport_protocol,
				buf3,
				ntohs(
						((struct sockaddr_in*) (struct sockaddr*) &(tmp->relayed_addr))->sin_port)

		);

		struct list_head* get1 = NULL;
		struct list_head* n1 = NULL;
		list_iterate_safe(get1, n1, &tmp->peers_permissions) {
			struct allocation_permission* tmp_per = list_get(get1,
					struct allocation_permission, list);

			/* check only the network address (not the port) */
			//	      if(tmp_per->family != addr->sa_family)
			//	      {
			//	        continue;
			//	      }
			// printf("permission_ip = %s \n",tmp_per->peer_addr);

		}
	}
}
