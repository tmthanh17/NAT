
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  
  /* Initialize any variables here */
  nat->mappings = NULL;
  nat->icmp_id_ext = MINIMUM_AUX_EXT;
  nat->tcp_port_ext = MINIMUM_AUX_EXT;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  struct sr_nat_mapping *mapping_node;
  struct sr_nat_mapping *mapping_node_next;
  struct sr_nat_connection *connection_node, *connection_node_next;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    for (mapping_node = nat->mappings; mapping_node != NULL; ) {
      if (mapping_node->type == nat_mapping_icmp) {
        if (difftime(curtime, mapping_node->last_updated) > nat->icmp_query_timeout) {
          mapping_node_next = mapping_node->next;
          sr_nat_destroy_mapping_node(nat, mapping_node);
          mapping_node = mapping_node_next;
        }
        else {
          mapping_node = mapping_node->next;
        }
      }
      else if (mapping_node->type == nat_mapping_tcp) {
        connection_node = mapping_node->conns;
        while (connection_node) {
          if ((connection_node->conn_state == tcp_conn_connected) && (difftime(curtime, connection_node->last_accessed) > nat->tcp_establish_idle_timeout)) { 
            connection_node_next = connection_node->next;
            sr_nat_destroy_connection_node(mapping_node, connection_node);
            connection_node = connection_node_next;
          }
          else if (((connection_node->conn_state == tcp_conn_time_wait) || (connection_node->conn_state == tcp_conn_outbound_syn)) &&
           (difftime(curtime, connection_node->last_accessed) > nat->tcp_transitory_idle_timeout)) {
            connection_node_next = connection_node->next;
            sr_nat_destroy_connection_node(mapping_node, connection_node);
            connection_node = connection_node_next;
          }
          else {
            connection_node = connection_node->next;
          }
        }
        if (mapping_node->conns == NULL) {
          /* No TCP connection */
          mapping_node_next = mapping_node->next;
          sr_nat_destroy_mapping_node(nat, mapping_node);
          mapping_node = mapping_node_next;
        }
        else {
          mapping_node = mapping_node->next;
        }
      }
      else {
        mapping_node = mapping_node->next;
      }
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping_node = NULL;
  for (mapping_node = nat->mappings; mapping_node != NULL; mapping_node = mapping_node->next) {
    if ((mapping_node->type == type) && (mapping_node->aux_ext == aux_ext)) {
      mapping_node->last_updated = time(NULL);
      copy = calloc(sizeof(struct sr_nat_mapping), 1);
      assert(copy);
      memcpy(copy, mapping_node, sizeof(struct sr_nat_mapping));
      break;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping_node = NULL;
  for (mapping_node = nat->mappings; mapping_node != NULL; mapping_node = mapping_node->next) {
    if ((mapping_node->type == type) && (mapping_node->ip_int == ip_int) && (mapping_node->aux_int == aux_int)) {
      mapping_node->last_updated = time(NULL);
      copy = calloc(sizeof(struct sr_nat_mapping), 1);
      assert(copy);
      memcpy(copy, mapping_node, sizeof(struct sr_nat_mapping));
      break;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping_node = sr_nat_create_mapping_node (nat, ip_int, aux_int, type);
  
  struct sr_nat_mapping *copy = calloc(sizeof(struct sr_nat_mapping), 1);
  memcpy (copy, mapping_node, sizeof(struct sr_nat_mapping));
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}




int sr_nat_verify_connection(struct sr_instance *sr) {
  if ((sr->nat)->connection == NAT_ENABLE) {
    return 1;
  }
  return 0;
}


static struct sr_nat_mapping *sr_nat_create_mapping_node(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {
  struct sr_nat_mapping *mapping_node = calloc (sizeof(struct sr_nat_mapping), 1);
  /* Store infomation before mapping*/
  mapping_node->type    = type;
  mapping_node->ip_int  = ip_int;
  mapping_node->aux_int = aux_int;
  mapping_node->last_updated = time(NULL);

  /* Transfer to external port or icmp id*/
  mapping_node->aux_ext = htons(sr_nat_aux_ext(nat, type));

  /* Add mapping to front of the list*/
  mapping_node->next = nat->mappings;
  nat->mappings = mapping_node;

  return mapping_node;
}



uint16_t sr_nat_aux_ext(struct sr_nat *nat, sr_nat_mapping_type type) {
  uint16_t aux_ext;
  struct sr_nat_mapping *mapping_node;
  if (type == nat_mapping_icmp){
    aux_ext = nat->icmp_id_ext;
  } 
  else if (type == nat_mapping_tcp) {
    aux_ext = nat->tcp_port_ext;
  }
  /* Check if a mapping of aux_ext already exists for port/id number*/
  for (mapping_node = nat->mappings; mapping_node != NULL; mapping_node = mapping_node->next) {
    if ((htons(aux_ext) == mapping_node->aux_ext) && (type == mapping_node->type)) {
      aux_ext = (aux_ext == MAXIMUM_AUX_EXT) ? MINIMUM_AUX_EXT : (aux_ext + 1);
      /* Turn back to check new value of aux_ext*/
      mapping_node = nat->mappings;
    }
  }
  /* Setup for the starting port/id for next mapping*/
  if (type == nat_mapping_icmp) {
    nat->icmp_id_ext = (aux_ext == MAXIMUM_AUX_EXT) ? MINIMUM_AUX_EXT : (aux_ext + 1);
  }
  else if (type == nat_mapping_tcp) {
    nat->tcp_port_ext = (aux_ext == MAXIMUM_AUX_EXT) ? MINIMUM_AUX_EXT : (aux_ext + 1);
  }
  return aux_ext;
}


static void sr_nat_destroy_mapping_node(struct sr_nat *nat, struct sr_nat_mapping *mapping_node) {
  struct sr_nat_mapping *current_node, *prev_node = NULL, *next_node = NULL;
  struct sr_nat_connection *curr_connection ;
  if (mapping_node) {
    for (current_node = nat->mappings; current_node != NULL; current_node = current_node->next) {
      if (current_node == mapping_node) {
        if (prev_node) {
          next_node = current_node->next;
          prev_node->next = next_node;
        }
        else {
          next_node = current_node->next;
          nat->mappings = next_node;
        }
        break;
      }
      prev_node = current_node;

    }
    /* Delete all list of connection in mapping_node */
    while (mapping_node->conns != NULL) {
      curr_connection = mapping_node->conns;
      mapping_node->conns = curr_connection->next;
      free(curr_connection);
    }
    free(mapping_node);
  }
}

static void sr_nat_destroy_connection_node(struct sr_nat_mapping *mapping_node, struct sr_nat_connection *connection_node) {
  struct sr_nat_connection *current_node, *prev_node = NULL, *next_node = NULL;
  if(mapping_node && connection_node) {
    for (current_node = mapping_node->conns; current_node != NULL; current_node = current_node->next) {
      if (current_node == connection_node) {
        if (prev_node) {
          next_node = current_node->next;
          prev_node->next = next_node;
        }
        else {
          next_node = current_node->next;
          mapping_node->conns = next_node;
        }
        break;
      }
      prev_node = current_node;
    }
    /**/ 
    while (current_node->QueuedInboundSyn != NULL){
      free(current_node->QueuedInboundSyn);
    }
    free(current_node);
  }
}

void sr_nat_outbound_icmp_packet(struct sr_instance *sr, uint8_t *packet, struct sr_nat_mapping *mapping_node) {
  struct sr_if *nexthop_if;
  struct sr_rt *rt;
  /*
  printf("Before mapping\n");
  print_hdrs(buf, len);
  */
 
  sr_ip_hdr_t *ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr_recv = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  uint16_t icmp_pkt_len = ntohs(ip_hdr_recv->ip_len) - sizeof(sr_ip_hdr_t);
  icmp_hdr_recv->icmp_id = mapping_node->aux_ext;
  icmp_hdr_recv->icmp_sum = 0;
  icmp_hdr_recv->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pkt_len);

  rt = rt_longest_prefix_match(sr, ip_hdr_recv->ip_dst);
  nexthop_if = sr_get_interface(sr, rt->interface);

  ip_hdr_recv->ip_src = nexthop_if->ip;
  ip_hdr_recv->ip_sum = 0;
  ip_hdr_recv->ip_sum = cksum(ip_hdr_recv, sizeof(sr_ip_hdr_t));
  
}

void sr_nat_inbound_icmp_packet(struct sr_instance *sr, uint8_t *packet, struct sr_nat_mapping *mapping_node) {
  struct sr_rt *rt;
  struct sr_if *nexthop_if;


  sr_ip_hdr_t *ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr_recv = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t icmp_pkt_len = ntohs(ip_hdr_recv->ip_len) - sizeof(sr_ip_hdr_t);

  icmp_hdr_recv->icmp_id = mapping_node->aux_int;
  icmp_hdr_recv->icmp_sum = 0;
  icmp_hdr_recv->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pkt_len);
 
  ip_hdr_recv->ip_dst = mapping_node->ip_int;
}



/*
        if (((icmp_hdr_recv->icmp_type == 8) || (icmp_hdr_recv->icmp_type == 0)) && (icmp_hdr_recv->icmp_code == 0)) {
				mapping_ext = sr_nat_lookup_external(sr->nat, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
				mapping_int = sr_nat_lookup_internal(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
				for (if_node = sr->if_list; if_node != NULL; if_node = if_node->next) {
					 Packet containing ICMP is destined for router's interface
					if ((ip_hdr_recv->ip_dst == if_node->ip) && (!mapping_int) && (!mapping_ext)) {
						printf("ICMP: Destination is router's interface\n");
						sr_icmp_pkt[0].send(sr, packet, interface, echo_reply);
						return;
					}
				}
				if (sr_verify_interface(interface) == INTERNAL_INTERFACE) {
					 I consider icmp_hdr_recv->type == 0 and icmp_hdr_recv->type == 0 because I assume that server 1/2 can ping to client 
					printf("Internal interface:  Receive ICMP request or reply\n");
					if (!mapping_int) {
						mapping_int = sr_nat_insert_mapping(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
					}
					
					printf("Before mapping\n");
					print_hdrs(packet, len);
					
					sr_nat_outbound_icmp_packet(sr, packet, len, interface, mapping_int);
					free(mapping_int);
				}
				else if (sr_verify_interface(interface) == EXTERNAL_INTERFACE) {
					printf("External interface:  Receive ICMP request or reply\n");
					if (!mapping_ext) {
						
					}
					sr_nat_inbound_icmp_packet(sr, packet, len, interface, mapping_ext);
					free(mapping_ext);
				}
				else {
					fprintf(stderr, "Not found interface\n");
				}
			}
			else {
				 I assume that there is one more router between server 1/2 and virtual router, so virtual router can receive ICMP error message from others router 
				printf(" Receive ICMP error from other routers");

			}
			
			break;

*/