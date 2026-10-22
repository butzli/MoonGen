// Software IPsec (ESP, AES-GCM) for MoonGen.
// Thin glue around DPDK's rte_ipsec library using synchronous CPU crypto
// (RTE_SECURITY_ACTION_TYPE_CPU_CRYPTO), e.g. with the ipsec_mb based
// crypto_aesni_gcm vdev. All ESP processing (header, IV, SQN, padding,
// trailer, ICV, tunnel encap/decap, anti-replay) is done by rte_ipsec.

#include <string.h>
#include <stdio.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_esp.h>
#include <rte_cryptodev.h>
#include <rte_security.h>
#include <rte_ipsec.h>

#define MG_IPSEC_ETH_LEN     14
#define MG_IPSEC_GCM_IV_LEN  12
#define MG_IPSEC_GCM_ICV_LEN 16
#define MG_IPSEC_GCM_AAD_LEN 8
#define MG_IPSEC_MAX_BURST   256

struct mg_ipsec_sa {
	struct rte_ipsec_session ss;   // must stay first, Lua passes this pointer around
	struct rte_ipsec_sa* sa;
	uint8_t hdr[MG_IPSEC_ETH_LEN + sizeof(struct rte_ipv4_hdr)];
	int outbound;
	int tunnel;
	uint32_t spi;
	uint32_t first_seq;           // ESP sequence number of the first/last packet received for this SA
	uint32_t last_seq;
	uint64_t seen;                 // packets received for this SA (before replay check and decryption)
};

struct mg_ipsec_rx_stats {
	uint64_t rx_pkts;       // all received frames
	uint64_t ok_pkts;       // successfully decrypted and authenticated
	uint64_t non_esp;       // not IPv4/ESP
	uint64_t unknown_spi;   // SPI outside of the configured range
	uint64_t prepare_drops; // replay window / malformed packets (rejected before decryption)
	uint64_t auth_fails;    // ICV check failed or invalid ESP trailer
};

// Payload of the generated packets: the UDP payload of the (inner) packet, the same with and without ESP, so that
// either receiver checks the traffic of either generator, also after a device in between has en- or decrypted it.
// magic | send time (reserved, 0) | sequence number of the flow | flow = 18 bytes, which fills a 60 byte frame.
// Host byte order; the fields are in this order so that each one is naturally aligned within the payload.
#define MG_PAYLOAD_MAGIC 0x504c4149 // "PLAI"
#define MG_FLOWS_MAX     4096       // flow ids above are counted as other packets
struct __rte_packed_begin mg_payload {
	uint32_t magic;
	uint32_t time;
	uint64_t seq;
	uint16_t flow;
} __rte_packed_end;
// offset of the payload in a frame built from a packet template: Ethernet, IPv4 without options, UDP
#define MG_PAYLOAD_OFF (MG_IPSEC_ETH_LEN + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr))

// Per-flow state of one receive queue: rx = 0 means the flow has not been seen on this queue yet.
struct mg_flow {
	uint64_t rx;   // packets received
	uint64_t lost; // sequence numbers skipped (everything before the first packet counts as skipped)
	uint64_t late; // sequence numbers from the past: reordered or duplicated
	uint64_t exp;  // next expected sequence number
};
struct mg_flows {
	uint64_t other; // packets without a valid payload
	struct mg_flow f[MG_FLOWS_MAX];
};

static int mg_cdev_id = -1;
static struct rte_mempool* mg_sess_pool;

// Check the payload of n packets whose IPv4 header starts at l3_off: count them per flow and find gaps.
// Fast path for IPv4 without options carrying UDP, which all generated packets are; anything else takes the
// general path or is counted as other.
static void mg_flows_check(struct mg_flows* fl, struct rte_mbuf** mb, uint16_t n, uint16_t l3_off) {
	const uint32_t fast_len = l3_off + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct mg_payload);
	for (uint16_t i = 0; i < n; i++) {
		struct rte_mbuf* m = mb[i];
		const uint8_t* ip = rte_pktmbuf_mtod_offset(m, const uint8_t*, l3_off);
		const struct mg_payload* p;
		if (likely(m->data_len >= fast_len && ip[0] == RTE_IPV4_VHL_DEF && ip[9] == IPPROTO_UDP)) {
			p = (const struct mg_payload*) (ip + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
		} else {
			uint32_t off = l3_off + sizeof(struct rte_ipv4_hdr);
			if (m->data_len < off || (ip[0] >> 4) != 4 || ip[9] != IPPROTO_UDP) {
				fl->other++;
				continue;
			}
			off = l3_off + (ip[0] & 0xf) * 4 + sizeof(struct rte_udp_hdr);
			if (m->data_len < off + sizeof(struct mg_payload)) {
				fl->other++;
				continue;
			}
			p = rte_pktmbuf_mtod_offset(m, const struct mg_payload*, off);
		}
		uint16_t id = p->flow;
		if (unlikely(p->magic != MG_PAYLOAD_MAGIC || id >= MG_FLOWS_MAX)) {
			fl->other++;
			continue;
		}
		struct mg_flow* f = &fl->f[id];
		uint64_t seq = p->seq;
		if (unlikely(!f->rx)) {
			// first packet of this flow on this queue: everything before it counts as missing
			f->lost = seq;
			f->exp = seq;
		}
		f->rx++;
		if (likely(seq >= f->exp)) {
			f->lost += seq - f->exp;
			f->exp = seq + 1;
		} else {
			// sequence number from the past: reordered or duplicated; it was counted as missing before
			f->late++;
		}
	}
}

// Complete receive step of the cleartext receiver: rx burst, check the payload, free.
// Returns the number of received packets.
uint16_t mg_plain_rx(uint16_t port, uint16_t queue, struct rte_mbuf** mb, uint16_t burst, struct mg_flows* fl) {
	uint16_t n = rte_eth_rx_burst(port, queue, mb, burst);
	if (n == 0) {
		return 0;
	}
	mg_flows_check(fl, mb, n, MG_IPSEC_ETH_LEN);
	rte_pktmbuf_free_bulk(mb, n);
	return n;
}

// Configure and start the crypto device (e.g. "crypto_aesni_gcm0", created via --vdev).
// Must be called once from the main task before any SA is created.
// Returns the crypto device id or a negative value on error.
int mg_ipsec_init(const char* cdev_name, uint32_t max_sessions, int socket) {
	if (mg_cdev_id >= 0) {
		return mg_cdev_id;
	}
	int dev_id = rte_cryptodev_get_dev_id(cdev_name);
	if (dev_id < 0) {
		printf("[ipsec] crypto device %s not found (missing --vdev=%s or libipsec-mb-dev at build time?)\n", cdev_name, cdev_name);
		return -1;
	}
	struct rte_cryptodev_info info;
	rte_cryptodev_info_get(dev_id, &info);
	if (!(info.feature_flags & RTE_CRYPTODEV_FF_SYM_CPU_CRYPTO)) {
		printf("[ipsec] crypto device %s does not support CPU crypto\n", cdev_name);
		return -1;
	}
	uint32_t sess_size = rte_cryptodev_sym_get_private_session_size(dev_id);
	mg_sess_pool = rte_cryptodev_sym_session_pool_create("mg_ipsec_sess", max_sessions, sess_size, 0, 0, socket);
	if (!mg_sess_pool) {
		printf("[ipsec] could not create session pool\n");
		return -1;
	}
	struct rte_cryptodev_config conf = {
		.socket_id = socket,
		.nb_queue_pairs = 1,
	};
	struct rte_cryptodev_qp_conf qp_conf = {
		.nb_descriptors = 2048,
		.mp_session = mg_sess_pool,
	};
	if (rte_cryptodev_configure(dev_id, &conf) < 0
	 || rte_cryptodev_queue_pair_setup(dev_id, 0, &qp_conf, socket) < 0
	 || rte_cryptodev_start(dev_id) < 0) {
		printf("[ipsec] could not configure/start crypto device %s\n", cdev_name);
		return -1;
	}
	mg_cdev_id = dev_id;
	return dev_id;
}

// Create an ESP SA with AES-GCM and a CPU crypto session.
// key: key_len (16 or 32) bytes AES key followed by the 4 byte salt (RFC 4106 layout).
// IPv4 addresses and SPI in host byte order. MACs are only used for outbound tunnel SAs:
// the tunnel template contains Ethernet + outer IPv4 header, so encrypted packets are ready to send.
// replay_win = 0 disables the anti-replay check (inbound only).
// esn: extended (64 bit) sequence numbers, RFC 4303: the packets still carry the low 32 bits only, the high
// 32 bits are part of the authenticated data.
struct mg_ipsec_sa* mg_ipsec_sa_create(int outbound, int tunnel, uint32_t spi,
		const uint8_t* key, uint32_t key_len, uint32_t replay_win, int esn,
		uint32_t src_ip, uint32_t dst_ip, const uint8_t* src_mac, const uint8_t* dst_mac, int socket) {
	if (mg_cdev_id < 0) {
		printf("[ipsec] mg_ipsec_init() has not been called\n");
		return NULL;
	}
	struct mg_ipsec_sa* s = rte_zmalloc_socket("mg_ipsec_sa", sizeof(*s), RTE_CACHE_LINE_SIZE, socket);
	if (!s) {
		return NULL;
	}
	s->outbound = outbound;
	s->tunnel = tunnel;
	s->spi = spi;

	struct rte_crypto_sym_xform xf = {
		.type = RTE_CRYPTO_SYM_XFORM_AEAD,
		.next = NULL,
		.aead = {
			.op = outbound ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT,
			.algo = RTE_CRYPTO_AEAD_AES_GCM,
			.key = { .data = key, .length = key_len },
			.iv = { .offset = 0, .length = MG_IPSEC_GCM_IV_LEN }, // offset is unused with CPU crypto
			.digest_length = MG_IPSEC_GCM_ICV_LEN,
			.aad_length = MG_IPSEC_GCM_AAD_LEN + (esn ? 4 : 0),
		},
	};

	struct rte_ipsec_sa_prm prm;
	memset(&prm, 0, sizeof(prm));
	prm.ipsec_xform.spi = spi;
	memcpy(&prm.ipsec_xform.salt, key + key_len, sizeof(prm.ipsec_xform.salt));
	prm.ipsec_xform.direction = outbound ? RTE_SECURITY_IPSEC_SA_DIR_EGRESS : RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	prm.ipsec_xform.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	prm.ipsec_xform.mode = tunnel ? RTE_SECURITY_IPSEC_SA_MODE_TUNNEL : RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT;
	prm.ipsec_xform.replay_win_sz = outbound ? 0 : replay_win;
	prm.ipsec_xform.options.esn = esn != 0;
	prm.crypto_xform = &xf;

	if (tunnel) {
		struct rte_ether_hdr* eth = (struct rte_ether_hdr*) s->hdr;
		struct rte_ipv4_hdr* ip = (struct rte_ipv4_hdr*) (s->hdr + MG_IPSEC_ETH_LEN);
		if (src_mac) memcpy(&eth->src_addr, src_mac, RTE_ETHER_ADDR_LEN);
		if (dst_mac) memcpy(&eth->dst_addr, dst_mac, RTE_ETHER_ADDR_LEN);
		eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		ip->version_ihl = RTE_IPV4_VHL_DEF;
		ip->time_to_live = 64;
		ip->next_proto_id = IPPROTO_ESP;
		ip->src_addr = rte_cpu_to_be_32(src_ip);
		ip->dst_addr = rte_cpu_to_be_32(dst_ip);
		prm.ipsec_xform.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
		prm.ipsec_xform.tunnel.ipv4.src_ip.s_addr = ip->src_addr;
		prm.ipsec_xform.tunnel.ipv4.dst_ip.s_addr = ip->dst_addr;
		prm.tun.hdr = s->hdr;
		prm.tun.hdr_len = sizeof(s->hdr);
		prm.tun.hdr_l3_off = MG_IPSEC_ETH_LEN;
		prm.tun.next_proto = IPPROTO_IPIP;
	} else {
		// rte_ipsec expects the IP version of the protected packet here, not the L4 protocol
		prm.trs.proto = IPPROTO_IPIP;
	}

	int size = rte_ipsec_sa_size(&prm);
	if (size < 0) {
		printf("[ipsec] rte_ipsec_sa_size failed: %d\n", size);
		goto err;
	}
	s->sa = rte_zmalloc_socket("mg_ipsec_rte_sa", size, RTE_CACHE_LINE_SIZE, socket);
	if (!s->sa) {
		goto err;
	}
	int rc = rte_ipsec_sa_init(s->sa, &prm, size);
	if (rc < 0) {
		printf("[ipsec] rte_ipsec_sa_init failed: %d\n", rc);
		goto err;
	}
	s->ss.sa = s->sa;
	s->ss.type = RTE_SECURITY_ACTION_TYPE_CPU_CRYPTO;
	s->ss.crypto.dev_id = mg_cdev_id;
	s->ss.crypto.ses = rte_cryptodev_sym_session_create(mg_cdev_id, &xf, mg_sess_pool);
	if (!s->ss.crypto.ses) {
		printf("[ipsec] could not create crypto session\n");
		goto err;
	}
	rc = rte_ipsec_session_prepare(&s->ss);
	if (rc < 0) {
		printf("[ipsec] rte_ipsec_session_prepare failed: %d\n", rc);
		goto err;
	}
	return s;

err:
	if (s->ss.crypto.ses) rte_cryptodev_sym_session_free(mg_cdev_id, s->ss.crypto.ses);
	if (s->sa) rte_free(s->sa);
	rte_free(s);
	return NULL;
}

void mg_ipsec_sa_destroy(struct mg_ipsec_sa* s) {
	if (!s) return;
	rte_cryptodev_sym_session_free(mg_cdev_id, s->ss.crypto.ses);
	rte_ipsec_sa_fini(s->sa);
	rte_free(s->sa);
	rte_free(s);
}

// Encrypt a burst of Ethernet/IPv4 packets in place.
// If tmpl is not NULL, it is copied into every mbuf first (the previous content was overwritten
// by the last in-place encryption of that mbuf, so pre-filled mempools do not survive). If seq is not NULL
// either, the template holds the generator payload (struct mg_payload) and every packet gets the next
// sequence number of the flow from *seq.
// Successfully encrypted packets are at mb[0..ret-1] and ready to send, failed ones are freed.
uint16_t mg_ipsec_encrypt_burst(struct mg_ipsec_sa* s, struct rte_mbuf** mb, uint16_t n,
		const uint8_t* tmpl, uint16_t tmpl_len, uint64_t* seq, uint64_t* fails) {
	for (uint16_t i = 0; i < n; i++) {
		struct rte_mbuf* m = mb[i];
		if (tmpl) {
			m->data_off = RTE_PKTMBUF_HEADROOM;
			rte_memcpy(rte_pktmbuf_mtod(m, void*), tmpl, tmpl_len);
			m->data_len = tmpl_len;
			m->pkt_len = tmpl_len;
		}
		m->l2_len = MG_IPSEC_ETH_LEN;
		m->l3_len = sizeof(struct rte_ipv4_hdr);
		// outer (tunnel) or modified (transport) IPv4 header checksum is computed by the NIC
		m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
	}
	// in a pass of its own: inside the loop above, it slows the copy loop down measurably
	if (tmpl && seq && tmpl_len >= MG_PAYLOAD_OFF + sizeof(struct mg_payload)) {
		// counted in a local: through the pointer, which may alias the payload, *seq is loaded and stored per packet
		uint64_t q = *seq;
		for (uint16_t i = 0; i < n; i++) {
			rte_pktmbuf_mtod_offset(mb[i], struct mg_payload*, MG_PAYLOAD_OFF)->seq = q++;
		}
		*seq = q;
	}
	uint16_t k = rte_ipsec_pkt_cpu_prepare(&s->ss, mb, n);
	k = rte_ipsec_pkt_process(&s->ss, mb, k);
	if (k < n) {
		*fails += n - k;
		rte_pktmbuf_free_bulk(mb + k, n - k);
	}
	return k;
}

// Decrypt a burst of received ESP packets for one SA in place (all packets must belong to this SA).
// Successfully decrypted packets are at mb[0..ret-1], rejected ones at the end (not freed).
// n - *prep_ok are replay/malformed rejects, *prep_ok - ret are ICV/trailer failures.
uint16_t mg_ipsec_decrypt_burst(struct mg_ipsec_sa* s, struct rte_mbuf** mb, uint16_t n, uint16_t* prep_ok) {
	for (uint16_t i = 0; i < n; i++) {
		struct rte_ipv4_hdr* ip = rte_pktmbuf_mtod_offset(mb[i], struct rte_ipv4_hdr*, MG_IPSEC_ETH_LEN);
		mb[i]->l2_len = MG_IPSEC_ETH_LEN;
		mb[i]->l3_len = rte_ipv4_hdr_len(ip);
	}
	uint16_t k = rte_ipsec_pkt_cpu_prepare(&s->ss, mb, n);
	*prep_ok = k;
	return rte_ipsec_pkt_process(&s->ss, mb, k);
}

// First and last ESP sequence number received for this SA by mg_ipsec_rx_decrypt and the number of
// packets in between; a difference means that packets of this SA were lost. Returns the number of packets seen.
uint64_t mg_ipsec_sa_rx_range(const struct mg_ipsec_sa* s, uint32_t* first, uint32_t* last) {
	*first = s->first_seq;
	*last = s->last_seq;
	return s->seen;
}

// Complete receive step: rx burst, SA lookup by SPI (sas[spi - spi_base]), decrypt, count, check the payload of
// the packets (if fl is not NULL; IPv4 header of a decrypted packet at l3_off: 0 in tunnel mode, where rte_ipsec
// removes the outer headers, 14 in transport mode, where it keeps the Ethernet header), free.
// With spi_base = 0 the SPIs are arbitrary (e.g. negotiated by IKE): sas is then a hash table with nb_sa slots
// (a power of two, at least one slot empty), indexed by the low bits of the SPI with linear probing.
// Returns the number of received packets.
uint16_t mg_ipsec_rx_decrypt(uint16_t port, uint16_t queue, struct rte_mbuf** mb, uint16_t burst,
		struct mg_ipsec_sa** sas, uint32_t nb_sa, uint32_t spi_base, struct mg_ipsec_rx_stats* st, struct mg_flows* fl,
		uint16_t l3_off) {
	if (burst > MG_IPSEC_MAX_BURST) {
		burst = MG_IPSEC_MAX_BURST;
	}
	uint16_t n = rte_eth_rx_burst(port, queue, mb, burst);
	if (n == 0) {
		return 0;
	}
	struct rte_mbuf* esp[MG_IPSEC_MAX_BURST];
	struct rte_mbuf* grp[MG_IPSEC_MAX_BURST];
	uint32_t idx[MG_IPSEC_MAX_BURST];
	uint16_t n_esp = 0;

	// classify by SPI
	for (uint16_t i = 0; i < n; i++) {
		struct rte_mbuf* m = mb[i];
		struct rte_ether_hdr* eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
		struct rte_ipv4_hdr* ip = (struct rte_ipv4_hdr*) (eth + 1);
		if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) || ip->next_proto_id != IPPROTO_ESP
		 || m->data_len < MG_IPSEC_ETH_LEN + rte_ipv4_hdr_len(ip) + sizeof(struct rte_esp_hdr)) {
			st->non_esp++;
			continue;
		}
		struct rte_esp_hdr* esph = (struct rte_esp_hdr*) ((uint8_t*) ip + rte_ipv4_hdr_len(ip));
		uint32_t spi = rte_be_to_cpu_32(esph->spi);
		uint32_t sa_idx = spi - spi_base;
		if (!spi_base) {
			sa_idx = spi & (nb_sa - 1);
			while (sas[sa_idx] && sas[sa_idx]->spi != spi) {
				sa_idx = (sa_idx + 1) & (nb_sa - 1);
			}
		}
		if (sa_idx >= nb_sa || !sas[sa_idx]) {
			st->unknown_spi++;
			continue;
		}
		uint32_t seq = rte_be_to_cpu_32(esph->seq);
		if (!sas[sa_idx]->seen++) {
			sas[sa_idx]->first_seq = seq;
		}
		sas[sa_idx]->last_seq = seq;
		esp[n_esp] = m;
		idx[n_esp] = sa_idx;
		n_esp++;
	}
	st->rx_pkts += n;

	// process groups of packets belonging to the same SA
	uint8_t done[MG_IPSEC_MAX_BURST] = {0};
	for (uint16_t i = 0; i < n_esp; i++) {
		if (done[i]) continue;
		uint32_t cur = idx[i];
		uint16_t g = 0;
		for (uint16_t j = i; j < n_esp; j++) {
			if (!done[j] && idx[j] == cur) {
				grp[g++] = esp[j];
				done[j] = 1;
			}
		}
		uint16_t prep_ok;
		uint16_t ok = mg_ipsec_decrypt_burst(sas[cur], grp, g, &prep_ok);
		st->prepare_drops += g - prep_ok;
		st->auth_fails += prep_ok - ok;
		st->ok_pkts += ok;
	}
	// the payload check runs in a pass of its own over the whole burst: inside the loop above, its mere call slows
	// that loop down by several percent; packets that were not decrypted have no valid payload there and count as other
	if (fl) {
		mg_flows_check(fl, mb, n, l3_off);
	}
	rte_pktmbuf_free_bulk(mb, n);
	return n;
}
