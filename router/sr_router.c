/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

#define ETH_ARP     1
#define ETH_IP      2
#define ETH_IP_ICMP 3

static int frame_type = 0;
sr_arp_pkt_t sr_arp_pkt[2] = { sr_send_arp_reply, sr_send_arp_request};
sr_icmp_pkt_t sr_icmp_pkt[2] = { sr_send_icmp_echo, sr_send_icmp_report};


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
	if ((sr->nat)->connection == NAT_ENABLE){
		printf("Enable NAT\n");
		if (sr_nat_init(sr->nat) != 0) {
			fprintf(stderr, "Fail enable NAT\n");
			return;
		}
	} else if ((sr->nat)->connection == NAT_DISABLE) {
		printf("Disable NAT\n");
	}

} /* -- sr_init -- */


bool sr_validate_packet(uint8_t *packet, unsigned int len)
{
	sr_ethernet_hdr_t *eth_hdr_recv;
	sr_ip_hdr_t *ip_hdr_recv;
	sr_icmp_hdr_t *icmp_hdr_recv;
	uint16_t cksum_iphdr = 0 , cksum_icmphdr = 0;
	unsigned int min_len = sizeof(sr_ethernet_hdr_t);
	if (len < min_len) {
		fprintf(stderr,"The length of received packet is smaller than minimum length of Ethernet\n");
		return false;
	}
	eth_hdr_recv = (sr_ethernet_hdr_t *) packet;
	printf("Frame: Ethernet");
	if (eth_hdr_recv->ether_type == ntohs(ethertype_arp)) {
		min_len += sizeof(sr_arp_hdr_t);
		if (len < min_len) {
			fprintf(stderr,"The length of received packet is smaller than minimum length of ARP\n");
		    return false;
		}
		frame_type = ETH_ARP;
		printf(" + ARP");
	}
	else if (eth_hdr_recv->ether_type == ntohs(ethertype_ip)) {
		min_len += sizeof(sr_ip_hdr_t);
		if (len < min_len) {
			fprintf(stderr,"The length of received packet is smaller than minimum length of IPv4\n");
		    return false;
		}
		ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
		cksum_iphdr = cksum(ip_hdr_recv, sizeof(sr_ip_hdr_t));
		if (cksum_iphdr != 0xFFFF) {
			fprintf(stderr, "Incorrect header checksum of IPv4");
			return false;
		}
		frame_type = ETH_IP;
		printf(" + IPv4");

		if (ip_hdr_recv->ip_p == ip_protocol_icmp) {
			min_len += sizeof(sr_icmp_hdr_t);
			if (len < min_len){
				fprintf(stderr,"The length of received packet is smaller than minimum length of ICMP\n");
				return false;
			}
			icmp_hdr_recv = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			cksum_icmphdr = cksum(icmp_hdr_recv, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
			if (cksum_icmphdr != 0xFFFF)
			{
				fprintf(stderr, "Incorrect header checksum of ICMP");
				return false;
			}
			frame_type = ETH_IP_ICMP;
			printf(" + ICMP");
		}

	}
	printf("\n");
	return true;
}

void sr_send_icmp_echo(struct sr_instance *sr, uint8_t *packet, char *interface_recv, enum sr_icmp_state icmp_state) {
	sr_ethernet_hdr_t *eth_hdr_recv = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t *icmp_hdr_recv = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	uint16_t payload_len = ntohs(ip_hdr_recv->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);
	uint16_t buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +sizeof(sr_icmp_hdr_t) + payload_len;
	uint8_t *buf = (uint8_t *) calloc(buf_len, 1);
	sr_ethernet_hdr_t *eth_hdr_reply = (sr_ethernet_hdr_t *) calloc(sizeof(sr_ethernet_hdr_t), 1);
	sr_ip_hdr_t *ip_hdr_reply = (sr_ip_hdr_t *) calloc(sizeof(sr_ip_hdr_t), 1);
	sr_icmp_hdr_t *icmp_pkt_reply = calloc(sizeof(sr_icmp_hdr_t) + payload_len, 1);
	if (icmp_state == echo_reply) {
		icmp_pkt_reply->icmp_type = 0;
		icmp_pkt_reply->icmp_code = 0;
	}
	else	
		return;
	icmp_pkt_reply->icmp_id = icmp_hdr_recv->icmp_id;
	icmp_pkt_reply->icmp_seqno = icmp_hdr_recv->icmp_seqno;
	memcpy((uint8_t *) icmp_pkt_reply + sizeof(sr_icmp_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), payload_len);
	icmp_pkt_reply->icmp_sum = 0;
	icmp_pkt_reply->icmp_sum = cksum(icmp_pkt_reply, sizeof(sr_icmp_hdr_t) + payload_len);

	ip_hdr_reply->ip_v   = ip_hdr_recv->ip_v;
	ip_hdr_reply->ip_hl  = ip_hdr_recv->ip_hl;
	ip_hdr_reply->ip_tos = ip_hdr_recv->ip_tos;
	ip_hdr_reply->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + payload_len);
	ip_hdr_reply->ip_id  = ip_hdr_recv->ip_id + 1;
	ip_hdr_reply->ip_off = htons(IP_DF);
	ip_hdr_reply->ip_ttl = 64;
	ip_hdr_reply->ip_p   = ip_protocol_icmp;
	ip_hdr_reply->ip_src = ip_hdr_recv->ip_dst;
	ip_hdr_reply->ip_dst = ip_hdr_recv->ip_src;
	ip_hdr_reply->ip_sum = 0;
	ip_hdr_reply->ip_sum = cksum(ip_hdr_reply, sizeof(sr_ip_hdr_t));

	memcpy(eth_hdr_reply->ether_dhost, eth_hdr_recv->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr_reply->ether_shost, eth_hdr_recv->ether_dhost, ETHER_ADDR_LEN);
	eth_hdr_reply->ether_type = htons(ethertype_ip);

	memcpy(buf, eth_hdr_reply, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_hdr_reply, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pkt_reply, sizeof(sr_icmp_hdr_t) + payload_len);
	
	/*print_hdrs(buf, buf_len);*/
	sr_send_packet(sr, buf, buf_len, interface_recv);

	free(eth_hdr_reply);
	free(ip_hdr_reply);
	free(icmp_pkt_reply);
	free(buf);
}

void sr_send_icmp_report(struct sr_instance *sr, uint8_t *packet, char *interface_recv, enum sr_icmp_state icmp_state) {
	sr_ethernet_hdr_t *eth_hdr_recv = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	uint16_t buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	uint8_t *buf = calloc(buf_len, 1);
	sr_ethernet_hdr_t *eth_hdr_reply = (sr_ethernet_hdr_t *) calloc(sizeof(sr_ethernet_hdr_t), 1);
	sr_ip_hdr_t *ip_hdr_reply = (sr_ip_hdr_t *) calloc(sizeof(sr_ip_hdr_t), 1);
	sr_icmp_t3_hdr_t *icmp_pkt_reply = (sr_icmp_t3_hdr_t *) calloc(sizeof(sr_icmp_t3_hdr_t), 1);

	switch (icmp_state) {
		case dst_net_unreachable:
			icmp_pkt_reply->icmp_type = 3;
			icmp_pkt_reply->icmp_code = 0;
			break;
		case dst_host_unreachable:
			icmp_pkt_reply->icmp_type = 3;
			icmp_pkt_reply->icmp_code = 1;
			break;
		case port_unreachable:
			icmp_pkt_reply->icmp_type = 3;
			icmp_pkt_reply->icmp_code = 3;
			break;
		case time_exceeded:
			icmp_pkt_reply->icmp_type = 11;
			icmp_pkt_reply->icmp_code = 0;
			break;
		default:
			return;
			break;
	}
	icmp_pkt_reply->unused = 0;
	icmp_pkt_reply->next_mtu = 0;
	memcpy(icmp_pkt_reply->data, (uint8_t *) packet + sizeof(sr_ethernet_hdr_t) , ICMP_DATA_SIZE);
	icmp_pkt_reply->icmp_sum = 0;
	icmp_pkt_reply->icmp_sum = cksum(icmp_pkt_reply, sizeof(sr_icmp_t3_hdr_t));

	ip_hdr_reply->ip_v = ip_hdr_recv->ip_v;
	ip_hdr_reply->ip_hl = ip_hdr_recv->ip_hl;
	ip_hdr_reply->ip_tos = ip_hdr_recv->ip_tos;
	ip_hdr_reply->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	ip_hdr_reply->ip_id  = ip_hdr_recv->ip_id + 1;
	ip_hdr_reply->ip_off = htons(IP_DF);
	ip_hdr_reply->ip_ttl = 64;
	ip_hdr_reply->ip_p   = ip_protocol_icmp;
	ip_hdr_reply->ip_src = ip_hdr_recv->ip_dst;
	ip_hdr_reply->ip_dst = ip_hdr_recv->ip_src;
	ip_hdr_reply->ip_sum = 0;
	ip_hdr_reply->ip_sum = cksum(ip_hdr_reply, sizeof(sr_ip_hdr_t));

	memcpy(eth_hdr_reply->ether_dhost, eth_hdr_recv->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr_reply->ether_shost, eth_hdr_recv->ether_dhost, ETHER_ADDR_LEN);
	eth_hdr_reply->ether_type = htons(ethertype_ip);

	memcpy(buf, eth_hdr_reply, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_hdr_reply, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pkt_reply, sizeof(sr_icmp_t3_hdr_t));
	/*
	print_hdrs(buf, buf_len);
	sr_send_packet(sr, buf, buf_len, interface_recv);
	*/
	free(eth_hdr_reply);
	free(ip_hdr_reply);
	free(icmp_pkt_reply);
	free(buf);

}



enum sr_icmp_state sr_forwarding_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint32_t ip_dst, char *interface_recv) {
	uint8_t *buf = calloc(len, 1);
	struct sr_rt *rt;
	struct sr_arpentry *entry;
	struct sr_arpreq *req;
	struct sr_if *nexthop_if;
	enum sr_icmp_state state = success;
	memcpy(buf, packet, len);


	struct sr_nat_mapping *mapping_int, *mapping_ext;
	sr_ip_hdr_t *ip_hdr_recv;
	sr_icmp_hdr_t *icmp_hdr_recv;


	
	if (((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_ttl == 1) {
		printf("Time Exceeded\n");
		free(buf);
		return state = time_exceeded;
	}
	rt = rt_longest_prefix_match(sr, ip_dst);
	if (!rt) {
		printf("Dest Net Unreachable\n");
		free(buf);
		return state = dst_net_unreachable;
	}
	nexthop_if = sr_get_interface(sr, rt->interface);
	entry = sr_arpcache_lookup(&sr->cache, ip_dst);
	
	if (entry) {
		/*use next_hop_ip->mac mapping in entry to send the packet*/
		memcpy(((sr_ethernet_hdr_t *) buf)->ether_dhost, entry->mac, ETHER_ADDR_LEN);
		memcpy(((sr_ethernet_hdr_t *) buf)->ether_shost, nexthop_if->addr, ETHER_ADDR_LEN);
		switch (frame_type) {
			case ETH_IP_ICMP:
				ip_hdr_recv = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
				icmp_hdr_recv = (sr_icmp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				if (((icmp_hdr_recv->icmp_type == 8) || (icmp_hdr_recv->icmp_type == 0)) && (icmp_hdr_recv->icmp_code == 0)) {
					mapping_int = sr_nat_lookup_internal(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
					mapping_ext = sr_nat_lookup_external(sr->nat, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
					
					if (sr_verify_interface(interface_recv) == INTERNAL_INTERFACE) {
						if (!mapping_int) {
							mapping_int = sr_nat_insert_mapping(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
						}
						
                        printf("Before mapping\n");
                        print_hdrs(buf, len);
                        
						sr_nat_outbound_icmp_packet(sr, buf, mapping_int);

						printf("After mapping internal \n");
						print_hdrs(buf, len);
						free(mapping_int);
					}
					
					/*
					else if (sr_verify_interface(interface_recv) == EXTERNAL_INTERFACE) {
						if (!mapping_ext) {
							return state;
						}
						sr_nat_inbound_icmp_packet(sr, buf, mapping_ext);
						printf("After mapping external \n");
						free(mapping_ext);
					}
					*/
				}
				break;
			default:
				break;
		}
		free(entry);
	} 
	else {
		printf("Lack MAC destination \n");
		print_hdrs(packet, len);
		req = sr_arpcache_queuereq(&sr->cache, ip_dst, packet, len, nexthop_if->name);
		state = sr_handle_arpreq(sr, req);
		return state;
	}
	/*
	switch (frame_type) {
		case ETH_IP_ICMP:
			if (((icmp_hdr_recv->icmp_type == 8) || (icmp_hdr_recv->icmp_type == 0)) && (icmp_hdr_recv->icmp_code == 0)) {
				mapping_int = sr_nat_lookup_internal(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
				mapping_ext = sr_nat_lookup_external(sr->nat, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
				if (sr_verify_interface(interface_recv) == INTERNAL_INTERFACE) {
					if (!mapping_int) {
						mapping_int = sr_nat_insert_mapping(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
					}
					sr_nat_outbound_icmp_packet(sr, buf, mapping_int);
					printf("After mapping internal \n");
					free(mapping_int);
				}
				
				else if (sr_verify_interface(interface_recv) == EXTERNAL_INTERFACE) {
					if (!mapping_ext) {
						return state;
					}
					sr_nat_inbound_icmp_packet(sr, buf, mapping_ext);
					printf("After mapping external \n");
					free(mapping_ext);
				}
				
			}
			break;
		
		default:
			break;
	}
	*/
	/*
	if (((icmp_hdr_recv->icmp_type == 8) || (icmp_hdr_recv->icmp_type == 0)) && (icmp_hdr_recv->icmp_code == 0)) {
		
		mapping_int = sr_nat_lookup_internal(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
		mapping_ext = sr_nat_lookup_external(sr->nat, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
		printf("interface: %s\n", interface_recv);
		if (sr_verify_interface(interface_recv) == INTERNAL_INTERFACE) {
			printf("Hle\n");
			if (!mapping_int) {
				 
				mapping_int = sr_nat_insert_mapping(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
			}
			
			sr_nat_outbound_icmp_packet(sr, buf, mapping_int);
			free(mapping_int);
		}
		else if (sr_verify_interface(interface_recv) == EXTERNAL_INTERFACE) {
			sr_nat_inbound_icmp_packet(sr, buf, mapping_ext);
			free(mapping_ext);
		}


	}
	*/

	((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_ttl--;
	((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_sum = 0;
	((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_sum = cksum((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)), sizeof(sr_ip_hdr_t));
	/*
	printf("Forwarding packet\n");
    print_hdrs(buf, len);
	*/
	sr_send_packet(sr, buf, len, nexthop_if->name);
	free(buf);
	return state;
}

void sr_processing_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	sr_arp_hdr_t *arp_hdr_recv;
	sr_ip_hdr_t *ip_hdr_recv;
	sr_icmp_hdr_t *icmp_hdr_recv;
	struct sr_if *if_node;
	struct sr_nat_mapping *mapping_int, *mapping_ext;
	struct sr_arpreq *req;
	struct sr_packet *pkt;
	enum sr_icmp_state state;


	switch (frame_type) {
		case ETH_ARP:
			arp_hdr_recv = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
			for (if_node = sr->if_list; if_node != NULL; if_node = if_node->next) {
				if (arp_hdr_recv->ar_tip == if_node->ip){
					if (arp_hdr_recv->ar_op == ntohs(arp_op_request)) {
						printf(" Receive ARP request\n");
						sr_arp_pkt[0].send(sr, if_node, arp_hdr_recv->ar_sip, arp_hdr_recv->ar_sha);
						break;
					}
					else if (arp_hdr_recv->ar_op == ntohs(arp_op_reply)) {
						printf("Receive ARP reply\n");
						req = sr_arpcache_insert(&sr->cache, arp_hdr_recv->ar_sha, arp_hdr_recv->ar_sip);
						if (req) {
							for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
								state = sr_forwarding_packet(sr, pkt->buf, pkt->len, arp_hdr_recv->ar_sip, interface);
							}
							sr_arpreq_destroy(&sr->cache, req);
						}
						break;
					}
				}
			}
			break;
		case ETH_IP:
			ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
			for (if_node = sr->if_list; if_node != NULL; if_node = if_node->next) {
				/* Packet containing TCP or UDP is destined for router's interface*/
				if (ip_hdr_recv->ip_dst == if_node->ip) {
					printf("UDP/TCP: Destination is router's interface\n");
					sr_icmp_pkt[1].send(sr, packet, interface, port_unreachable);
					return;
				}
			}
			/* Packet should be forward */
			printf("UDP/TCP: Destination is not router's interface\n");


			break;
		case ETH_IP_ICMP:
			ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
			icmp_hdr_recv = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			
			mapping_ext = sr_nat_lookup_external(sr->nat, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
			mapping_int = sr_nat_lookup_internal(sr->nat, ip_hdr_recv->ip_src, icmp_hdr_recv->icmp_id, nat_mapping_icmp);
			for (if_node = sr->if_list; if_node != NULL; if_node = if_node->next) {
				/* Packet containing ICMP is destined for router's interface*/
				if ((ip_hdr_recv->ip_dst == if_node->ip) && (!mapping_ext) && (!mapping_int)) {
					printf("ICMP: Destination is router's interface\n");
					sr_icmp_pkt[0].send(sr, packet, interface, echo_reply);
					return;
				}
			}
			/* Packet should be forward */
			printf("ICMP: Destination is not router's interface, packet should be forwarded\n");
			state = sr_forwarding_packet(sr, packet, len, ip_hdr_recv->ip_dst, interface);
			if (state != success)
			{
				printf("ICMP: Packet has problem\n");
				sr_icmp_pkt[1].send(sr, packet, interface, state);
			}
			break;				
	}
}
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router 
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
	if (sr_validate_packet(packet, len) == false) {
		printf("Failed packet\n");
		return;
	}

	sr_processing_packet(sr, packet, len, interface);
  

}/* end sr_ForwardPacket */

