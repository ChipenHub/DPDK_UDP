#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#define ENABLE_ARP			1
#define ENABLE_ICMP			1
#define ENABLE_ARP_REPLY	1
#define ENABLE_DEBUG		1
#define ENABLE_TIMER		1
#define ENABLE_RINGBUFFER	1
#define ENABLE_MULTITHREAD	1
#define ENABLE_UDP_APP		1

#define RING_SIZE 			1024
#define NUM_MBUFS 			8191
#define MBUF_CACHE_SIZE 	250
#define RX_RING_SIZE 		1024
#define TX_RING_SIZE 		1024
#define PKT_BURST 			32
#define BURST_SIZE			32


#define TIMER_RESOLUTION_CYCLES 60000000000ULL

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 0, 120);

static uint16_t gDpdkPortId = 0;
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
static uint32_t gSrcIp;		// 大端存储
static uint32_t gDstIp;
static uint16_t gSrcPort;
static uint16_t gDstPort;

static struct rte_mempool *mbuf_pool = NULL;

#if ENABLE_ARP_REPLY
#include "arp.h"
static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
#endif

#if ENABLE_RINGBUFFER

struct inout_ring {

	struct rte_ring *in;
	struct rte_ring *out;

};

static struct inout_ring *rInst = NULL;

struct inout_ring *ring_instance(void) {

	if (rInst == NULL) {

		rInst = rte_malloc("in/out ring", sizeof (struct inout_ring), 0);

		memset(rInst, 0, sizeof (struct inout_ring));
	
	}

	return rInst;

}

#endif








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

#if ENABLE_ARP
struct rte_mbuf* encode_arp_pktmbuf(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
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

	// 修复：正确处理 dst_mac 为 NULL 的情况
	if (dst_mac == NULL || !strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
		// 广播地址
		memset(eth->dst_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}

	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(opcode);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	
	if (dst_mac == NULL) {
		memset(arp->arp_data.arp_tha.addr_bytes, 0x00, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;

	return mbuf;
}
#endif

#if ENABLE_ICMP
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
	icmp->icmp_type = 0;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));

	return mbuf;
}
#endif

static inline void
print_ether_addr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

#if ENABLE_TIMER
static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {
	printf("ARP timer callback started\n");
	
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ring_instance();
	if (mbuf_pool == NULL) {
		printf("Error: mbuf_pool is NULL in timer callback\n");
		return;
	}

	printf("arp_request ---> ");

	int i = 0; 
	for (i = 1; i < 255; i++) {
		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
		uint8_t* dstmac = get_dst_macaddr(dstip);

		struct in_addr addr;
		addr.s_addr = dstip;
		printf("%s ", inet_ntoa(addr));

		// 修复：无论 dstmac 是否为 NULL，都可以发送 ARP 请求
		struct rte_mbuf * arp_buf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		if (arp_buf != NULL) {
			// uint16_t nb_tx = rte_eth_tx_burst(gDpdkPortId, 0, &arp_buf, 1);
			uint16_t nb_tx = rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_buf, 1, NULL);
			if (nb_tx != 1) {
				printf("Failed to send ARP request for IP %s\n", inet_ntoa(addr));
			}
			// rte_pktmbuf_free(arp_buf);
		}
	}
	puts("");
}
#endif





#if ENABLE_MULTITHREAD

static int
packet_process(__rte_unused void *arg)
{

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;

	struct inout_ring *ring = ring_instance();

	while (1) {


		struct rte_mbuf* mbufs[BURST_SIZE];
		
		unsigned nb_rx = rte_ring_mc_dequeue_burst(ring->in, (void **)mbufs, BURST_SIZE, NULL); 

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
			rte_memcpy(gDstMac, ehdr->src_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
#if ENABLE_ARP
				struct rte_arp_hdr *ahdr = (struct rte_arp_hdr *)(ehdr + 1);

				if (ahdr->arp_data.arp_tip != gSrcIp) {
					rte_pktmbuf_free(mbufs[i]);
					continue;
				}
				
				if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
					struct in_addr addr;
					addr.s_addr = ahdr->arp_data.arp_sip;
					printf("arp ---> src: %s", inet_ntoa(addr));

					addr.s_addr = ahdr->arp_data.arp_tip;
					printf("  local: %s\n", inet_ntoa(addr));

					struct rte_mbuf *arpbuf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes,
						ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
					
					// rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
					// rte_pktmbuf_free(arpbuf);

					rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
					
					printf("ARP enqueue finished\n");
					

					rte_pktmbuf_free(mbufs[i]);
					continue;
				}
#endif

#if ENABLE_ARP_REPLY
				else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
					struct arp_table *table = arp_table_instance();
					uint8_t *hwaddr = get_dst_macaddr(ahdr->arp_data.arp_sip);
					if (hwaddr == NULL) {
						struct arp_entry *entry = rte_malloc("arp entry", sizeof(struct arp_entry), 0);
						if (entry) {
							memset(entry, 0, sizeof(struct arp_entry));
							entry->ip = ahdr->arp_data.arp_sip;
							rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
							entry->status = ARP_ENTRY_STATIC_DYNAMIC;

							LL_ADD(entry, table->entries);
							table->count++;
						}
					}
#if ENABLE_DEBUG
					struct arp_entry *iter;
					for (iter = table->entries; iter != NULL; iter = iter->next) {
						print_ether_addr("arp entry ---> mac: ", (struct rte_ether_addr *) iter->hwaddr);
						struct in_addr addr;
						addr.s_addr = iter->ip;
						printf(" ---> src: %s\n", inet_ntoa(addr));
					}
#endif
				}
				
				rte_pktmbuf_free(mbufs[i]);	
				continue;
#endif
			}
			
		    if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);
				
		   		if (ip_hdr->next_proto_id == IPPROTO_UDP) {
					if (ip_hdr->dst_addr != gSrcIp) {
						rte_pktmbuf_free(mbufs[i]);
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
					// rte_eth_tx_burst(gDpdkPortId, 0, &udpbuf, 1);
					rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);
					printf("UDP enqueue finished\n");
					
					// rte_pktmbuf_free(udpbuf);
					rte_pktmbuf_free(mbufs[i]);
					continue;
				}

#if ENABLE_ICMP
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

						
						rte_ring_mp_enqueue_burst(ring->out, (void **)&txbuf, 1, NULL);
							// rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
						
						// rte_pktmbuf_free(txbuf);
						rte_pktmbuf_free(mbufs[i]);
					}
				}
#endif
		    }
			
			// 如果包没有被处理，释放它
			if (mbufs[i] != NULL) {
				rte_pktmbuf_free(mbufs[i]);
			}
        }


	}

}


#endif

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
	gSrcIp = gLocalIp;
    gSrcPort = rte_cpu_to_be_16(8088);

// 初始化定时器
#if ENABLE_TIMER
	rte_timer_subsystem_init();

	static struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	printf("Timer setup - hz: %lu, lcore_id: %u\n", hz, lcore_id);
	
	ret = rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);
	if (ret != 0) {
		printf("Failed to reset timer: %d\n", ret);
	} else {
		printf("Timer reset successfully\n");
	}
#endif

// 初始化 inout ring
#if ENABLE_RINGBUFFER


	struct inout_ring *ring = ring_instance();
	if (ring == NULL) {

		rte_exit(EXIT_FAILURE, "ring buffer init failed");
		
	}

	if (ring->in == NULL) {

		ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

	if (ring->out == NULL) {

		ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	
	
#endif

#if ENABLE_MULTITHREAD

	
	rte_eal_remote_launch(packet_process, mbuf_pool, rte_get_next_lcore(lcore_id, 1, 0));
	// 只按照逻辑顺序挑选下一个节点，不考虑 NUMA 节点的位置。



#endif




    // 主循环：接收和处理数据包
    while (1) {
        struct rte_mbuf *rx[PKT_BURST];
        uint16_t nb_rx = rte_eth_rx_burst(gDpdkPortId, 0, rx, PKT_BURST);
		if (nb_rx > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (nb_rx > 0) {

			rte_ring_sp_enqueue_burst(ring->in, (void **)rx, nb_rx, NULL);
	
		}

		// tx
		struct rte_mbuf *tx[PKT_BURST];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {

			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

			unsigned int i = 0;
			for (i = 0; i < nb_tx; i++) {
				rte_pktmbuf_free(tx[i]);
			}
			
		}





#if ENABLE_TIMER
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
#endif
    }

    // 清理
    rte_eth_dev_stop(gDpdkPortId);
    rte_eth_dev_close(gDpdkPortId);
    rte_eal_cleanup();
    return 0;
}
