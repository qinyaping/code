
#ifndef TURNSERVER_H
#define TURNSERVER_H

#include <string>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include "list.h"
#include "Lock.h"

#ifndef _POSIX_REALTIME_SIGNALS
#error "POSIX realtime signals not supported!"
#endif

/**
 * \def SIGRT_EXPIRE_ALLOCATION
 * \brief Signal value when an allocation expires.
 */
#define SIGRT_EXPIRE_ALLOCATION (SIGRTMIN)

/**
 * \def SIGRT_EXPIRE_PERMISSION
 * \brief Signal value when a permission expires.
 */
#define SIGRT_EXPIRE_PERMISSION (SIGRTMIN + 1)

/**
 * \def SIGRT_EXPIRE_CHANNEL
 * \brief Signal value when channel expires.
 */
#define SIGRT_EXPIRE_CHANNEL (SIGRTMIN + 2)

/**
 * \def SIGRT_EXPIRE_TOKEN
 * \brief Signal value when token expires.
 */
#define SIGRT_EXPIRE_TOKEN (SIGRTMIN + 3)

/**
 * \def SIGRT_EXPIRE_TCP_RELAY
 * \brief Signal value when TCP relay expires (no ConnectionBind received).
 */
#define SIGRT_EXPIRE_TCP_RELAY (SIGRTMIN + 4)

/**
 * \struct denied_address
 * \brief Describes an address.
 */
struct denied_address
{
  int family; /**< AF family (AF_INET or AF_INET6) */
  uint8_t addr[16]; /**< IPv4 or IPv6 address */
  uint8_t mask; /**< Network mask of the address */
  uint16_t port; /**< Port */
  struct list_head list; /**< For list management */
};

struct listen_sockets
{
  int sock_tcp; /**< Listen TCP socket */
  int sock_udp; /**< Listen UDP socket */
  struct tls_peer* sock_tls; /**< Listen TLS socket */
  struct tls_peer* sock_dtls; /**< Listen DTLS socket */
};

/**
 * \struct socket_desc
 * \brief Descriptor for TCP client connected.
 *
 * It contains a buffer for TCP segment reconstruction.
 */
struct socket_desc
{
  int sock; /**< Socket descriptor */
  char buf[1500]; /**< Internal buffer for TCP stream reconstruction */
  size_t buf_pos; /**< Position in the internal buffer */
  size_t msg_len; /**< Message length that is not complete */
  int tls; /**< If socket uses TLS */
  struct list_head list; /**< For list management */
};

class Udp_Handle;

class TurnServer
{
public:
	TurnServer(Udp_Handle* pHandler);
	int TurnServer::turnserver_start(int argc, char** argv);
	void handler_receive_client(unsigned char * data,unsigned int len,std::string SourceAddr,unsigned int SourcePort);
	void handler_receive_relay(unsigned char * data,unsigned int len,std::string SourceAddr,unsigned int SourcePort, int peer_relay_socket);
	int turnserver_expire();

protected:
	void init_turnserver_data_list();
	bool init_turnserver();
	void turnserver_cleanup(void* arg);
	void set_signal_handler();
	void deal_expire_thing();

	int turn_send_message_asyn(int transport_protocol, int sock, struct tls_peer* speer,
			const struct sockaddr* addr, socklen_t addr_size, size_t total_len,
			const struct iovec* iov, size_t iovlen);
	int turnserver_listen_recv(int transport_protocol, int sock,
	    const char* buf, ssize_t buflen, const struct sockaddr* saddr,
	    const struct sockaddr* daddr, socklen_t saddr_size,
	    struct list_head* allocation_list, struct list_head* account_list,
	    struct tls_peer* speer);
	int turnserver_process_turn(int transport_protocol, int sock,
	    const struct turn_message* message, const struct sockaddr* saddr,
	    const struct sockaddr* daddr, socklen_t saddr_size,
	    struct list_head* allocation_list, struct account_desc* account,
	    struct tls_peer* speer);
	int turnserver_process_binding_request(int transport_protocol, int sock,
	    const struct turn_message* message, const struct sockaddr* saddr,
	    socklen_t saddr_size, struct tls_peer* speer);
	int turnserver_process_allocate_request(int transport_protocol, int sock,
	    const struct turn_message* message, const struct sockaddr* saddr,
	    const struct sockaddr* daddr, socklen_t saddr_size,
	    struct list_head* allocation_list, struct account_desc* account,
	    struct tls_peer* speer);
	int turnserver_process_refresh_request(int transport_protocol, int sock,
	    const struct turn_message* message, const struct sockaddr* saddr,
	    socklen_t saddr_size, struct list_head* allocation_list,
	    struct allocation_desc* desc, struct account_desc* account,
	    struct tls_peer* speer);
	int turnserver_process_createpermission_request(int transport_protocol,
	    int sock, const struct turn_message* message, const struct sockaddr* saddr,
	    socklen_t saddr_size, struct allocation_desc* desc, struct tls_peer* speer);
	int turnserver_process_send_indication(
			const struct turn_message* message, struct allocation_desc* desc);
	int turnserver_process_channelbind_request(int transport_protocol,
	    int sock, const struct turn_message* message, const struct sockaddr* saddr,
	    socklen_t saddr_size, struct allocation_desc* desc, struct tls_peer* speer);
	int turnserver_process_channeldata(int transport_protocol,
	    uint16_t channel_number, const char* buf, ssize_t buflen,
	    const struct sockaddr* saddr, const struct sockaddr* daddr,
	    socklen_t saddr_size, struct list_head* allocation_list);
	int turnserver_send_error(int transport_protocol, int sock, int method,
	    const uint8_t* id, int error, const struct sockaddr* saddr,
	    socklen_t saddr_size, struct tls_peer* speer, unsigned char* key);
	int turnserver_relayed_recv(const char* buf, ssize_t buflen,
			const struct sockaddr* saddr, struct sockaddr* daddr,
			socklen_t saddr_size, struct list_head* allocation_list,
			struct tls_peer* speer);

public:
	  Udp_Handle* m_pHandler;
	  struct list_head allocation_list;
	  //CMutex m_allocation_lock;

	  struct list_head account_list;
	  //CMutex m_account_lock;

	  struct list_head g_token_list;
	  //CMutex m_token_lock;

//	  struct list_head g_expired_allocation_list;
//	  struct list_head g_expired_permission_list;
//	  struct list_head g_expired_channel_list;
//	  struct list_head g_expired_token_list;

//	  volatile sig_atomic_t g_run = 0;
//	  volatile sig_atomic_t g_reinit = 0;

	  struct listen_sockets sockets;

	  struct sigaction sa;

	  std::string configure_path;

};


#endif /* TURNSERVER_H */

