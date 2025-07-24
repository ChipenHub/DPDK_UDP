#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#define ENABLE_UDP		1
#define ENABLE_ARP		1
#define ENABLE_ICMP		1


#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define PKT_BURST 32

static uint16_t gDpdkPortId = 0;
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
static uint32_t gSrcIp;
static uint32_t gDstIp;
static uint16_t gSrcPort;
static uint16_t gDstPort;

static struct rte_mempool *mbuf_pool = NULL;

// 计算校验和
static uint16_t checksum(uint16_t *addr, int count) {

	register long sum = 0;

	while (count > 1) {

		sum += *(unsigned short*)addr++;
		count -= 2;
	
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;

}

// 初始化网卡
static int init_port(uint16_t port_id) {
    struct rte_eth_conf port_conf = {0};
    struct rte_eth_dev_info dev_info;
    int ret;

	/*
	uint16_t num_sys_ports = rte_eth_dev_conut_avail();
	if (num_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No Support eth found");
	*/

    // 1. 获取网卡信息
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        printf("Error: Failed to get device info for port %u\n", port_id);
        return ret;
    }

    // 2. 配置 RX 和 TX 队列的数量
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret != 0) {
        printf("Error: Failed to configure port %u\n", port_id);
        return ret;
    }

    // 3. 设置 RX 队列
    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, 
                                 rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    if (ret < 0) {
        printf("Error: Failed to setup RX queue for port %u\n", port_id);
        return ret;
    }

    // 4. 设置 TX 队列
    ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, 
                                 rte_eth_dev_socket_id(port_id), NULL);
    if (ret < 0) {
        printf("Error: Failed to setup TX queue for port %u\n", port_id);
        return ret;
    }

    // 启动网卡
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Error: Failed to start port %u\n", port_id);
        return ret;
    }

    // 启用混杂模式
    rte_eth_promiscuous_enable(port_id);
    printf("Port %u initialized, promiscuous mode enabled\n", port_id);

    // 获取源 MAC 地址
    rte_eth_macaddr_get(port_id, (struct rte_ether_addr *)gSrcMac);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           gSrcMac[0], gSrcMac[1], gSrcMac[2], gSrcMac[3], gSrcMac[4], gSrcMac[5]);

    return 0;
}

// 构造 UDP 数据包
struct rte_mbuf* encode_udp_pktbuf(struct rte_mempool *mbuf_pool, uint16_t port_id, const char *data, int len) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Error: Failed to allocate mbuf\n");
    }

    // 以太网头部
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IPv4 头部
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + len);
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->src_addr = gSrcIp;
    ip_hdr->dst_addr = gDstIp;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct rte_ipv4_hdr));

    // UDP 头部
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    udp_hdr->src_port = gSrcPort;
    udp_hdr->dst_port = gDstPort;
    udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + len);
    udp_hdr->dgram_cksum = 0; // UDP 校验和可选，设为 0

    // 数据载荷
    char *payload = (char *)(udp_hdr + 1);
    memcpy(payload, data, len);

    // 设置 mbuf
    mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + len;
    mbuf->pkt_len = mbuf->data_len;

	return mbuf;

}


struct rte_mbuf* encode_arp_pktmbuf(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Error: Failed to allocate mbuf\n");
    }

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);


	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
	rte_memcpy(eth->src_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(2);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;

	return mbuf;
}


struct rte_mbuf *encode_icmp_pktbuf(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}

	
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);

	// 1 ether
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
	rte_memcpy(eth->src_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2 ip
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt_data + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 icmp 
	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(pkt_data+ sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));


	return mbuf;

}


int main(int argc, char *argv[]) {
    int ret;

    // 初始化 EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error: Cannot init EAL\n");
    }

    // 创建内存池
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Error: Cannot create mbuf pool\n");
    }

    // 初始化端口
    gDpdkPortId = 0; // 使用端口 0（0000:03:00.0）
    ret = init_port(gDpdkPortId);
    if (ret != 0) {
        rte_exit(EXIT_FAILURE, "Error: Cannot init port %u\n", gDpdkPortId);
    }


    // 设置 IP 和端口
	inet_pton(AF_INET, "192.168.0.120", &gSrcIp);
    gSrcPort = rte_cpu_to_be_16(8088);
    

    // 主循环：接收和处理数据包
    while (1) {
        struct rte_mbuf *bufs[PKT_BURST];
        uint16_t nb_rx = rte_eth_rx_burst(gDpdkPortId, 0, bufs, PKT_BURST);
        for (uint16_t i = 0; i < nb_rx; i++) {
            
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
			rte_memcpy(gDstMac, ehdr->src_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

#if		ENABLE_ARP 		// 
						if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
			
							struct rte_arp_hdr *ahdr = (struct rte_arp_hdr *)(ehdr + 1);
							// struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], 
							//	struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
			
			
			
							if (ahdr->arp_data.arp_tip != gSrcIp) { // 关键判断
			
								rte_pktmbuf_free(bufs[i]);
							
								continue;
			
							}
			
							struct in_addr addr;
							addr.s_addr = ahdr->arp_data.arp_sip;
							printf("arp ---> src: %s", inet_ntoa(addr));
			
							
							addr.s_addr = ahdr->arp_data.arp_tip;
							printf("  local: %s\n", inet_ntoa(addr));
			
							struct rte_mbuf *arpbuf = encode_arp_pktmbuf(mbuf_pool, ahdr->arp_data.arp_sha.addr_bytes,
								ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
							
							rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
			
							printf("ARP reply finished\n");
							
							rte_pktmbuf_free(arpbuf);
							rte_pktmbuf_free(bufs[i]);
							
							continue;
							
						}
			
#endif

		    if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);


			
		   		if (ip_hdr->next_proto_id == IPPROTO_UDP) {
					struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);	
					if (ip_hdr->next_proto_id != IPPROTO_UDP || ip_hdr->dst_addr != gSrcIp) {
						
						rte_pktmbuf_free(bufs[i]);
						continue;
					
					}
	
	
					struct in_addr addr;
					addr.s_addr = ip_hdr->src_addr;
					printf("udp ---> src: %s", inet_ntoa(addr));
					
					addr.s_addr = ip_hdr->dst_addr;
					printf("  local: %s", inet_ntoa(addr));
	
					struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
					
					rte_memcpy(&gDstIp, &ip_hdr->src_addr, sizeof(uint32_t));
					rte_memcpy(&gDstPort, &udp_hdr->src_port, sizeof(uint16_t));
					
	
					char *payload = (char *)(udp_hdr + 1);
					uint16_t payload_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);
					payload[payload_len] = '\0'; // 确保字符串终止
	
					printf("  content: %s\n", payload);
	
					// 封装数据包
					struct rte_mbuf *udpbuf = encode_udp_pktbuf(mbuf_pool, gDpdkPortId, payload, payload_len);
					
					rte_eth_tx_burst(gDpdkPortId, 0, &udpbuf, 1);
	
					printf("UDP reply finished\n");
					
					rte_pktmbuf_free(udpbuf);
					rte_pktmbuf_free(bufs[i]);
	
					continue;

				}



			
#if ENABLE_ICMP


				

				if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
						
			
						if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
			
							struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(ip_hdr + 1);
							
							if (icmphdr->icmp_type == 8) {
			
								struct in_addr addr;
								addr.s_addr = ip_hdr->src_addr;
								printf("icmp ---> src: %s", inet_ntoa(addr));
								addr.s_addr = ip_hdr->dst_addr;
								printf("  local: %s, type: %d\n", inet_ntoa(addr), icmphdr->icmp_type);
							
			
								struct rte_mbuf *txbuf = encode_icmp_pktbuf(mbuf_pool, ehdr->src_addr.addr_bytes,
									ip_hdr->dst_addr, ip_hdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
			
								rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
								
								rte_pktmbuf_free(txbuf);
								rte_pktmbuf_free(bufs[i]);
							}
							
			
						}
			
					}
#endif

				
				
		    }


		



			
        }
    }

    // 清理
    rte_eth_dev_stop(gDpdkPortId);
    rte_eth_dev_close(gDpdkPortId);
    rte_eal_cleanup();
    return 0;
}
