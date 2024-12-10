
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_router.h"
#include "sr_if.h"


#define DEFAULT_ICMP_QUERY_TIMEOUT          60
#define DEFAULT_TCP_ESTABLISH_IDLE_TIMEOUT  7440
#define DEFAULT_TCP_TRANSITORY_IDLE_TIMEOUT 300

#define NAT_DISABLE 0
#define NAT_ENABLE  1

#define MINIMUM_AUX_EXT  50000
#define MAXIMUM_AUX_EXT  59999
#define SIMULTANIOUS_OPEN_WAIT_TIME  6

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;



typedef enum {
  tcp_conn_outbound_syn,
  tcp_conn_inbound_syn_pending,
  tcp_conn_connected,
  tcp_conn_time_wait
}sr_nat_tcp_conn_state_t;



struct sr_nat_connection {
  /* add TCP connection state data members here */
  sr_nat_tcp_conn_state_t conn_state;
  time_t last_accessed;
  sr_ip_hdr_t *QueuedInboundSyn;
  
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  int icmp_query_timeout ;
  int tcp_establish_idle_timeout;
  int tcp_transitory_idle_timeout;
  int16_t icmp_id_ext;
  int16_t tcp_port_ext;
  int connection;
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );



int sr_nat_verify_connection(struct sr_instance *sr);
uint16_t sr_nat_aux_ext(struct sr_nat *nat, sr_nat_mapping_type type);
static void sr_nat_destroy_mapping_node(struct sr_nat *nat, struct sr_nat_mapping *mapping_node);
static void sr_nat_destroy_connection_node(struct sr_nat_mapping *mapping_node, struct sr_nat_connection *connection_node);
static struct sr_nat_mapping *sr_nat_create_mapping_node(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);
void sr_nat_outbound_icmp_packet(struct sr_instance *sr, uint8_t *packet, struct sr_nat_mapping *mapping_node);
void sr_nat_inbound_icmp_packet(struct sr_instance *sr, uint8_t *packet, struct sr_nat_mapping *mapping_node);
#endif