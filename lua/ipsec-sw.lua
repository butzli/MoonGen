---------------------------------
--- @file ipsec-sw.lua
--- @brief Software IPsec (ESP, AES-GCM) based on DPDK rte_ipsec + CPU crypto (ipsec_mb).
--- Requires the crypto vdev in the DPDK config, e.g. cli = { "--vdev=crypto_aesni_gcm0" },
--- and DPDK built with libipsec-mb-dev installed.
--- Also holds what the cleartext programs (plain-*.lua) share with the IPsec ones: the generator payload and its
--- check per flow, the latency measurement, the NIC steering by rte_flow and the NIC pacing.
---------------------------------

local ffi = require "ffi"
local log = require "log"
-- rte_flow declarations
require "filter"

local C = ffi.C

-- functions and structs of src/ipsec-sw.c, described there
ffi.cdef[[
	struct mg_ipsec_sa;

	struct mg_ipsec_rx_stats {
		uint64_t rx_pkts;
		uint64_t ok_pkts;
		uint64_t non_esp;
		uint64_t unknown_spi;
		uint64_t prepare_drops;
		uint64_t auth_fails;
	};

	int mg_ipsec_init(const char* cdev_name, uint32_t max_sessions, int socket);
	struct mg_ipsec_sa* mg_ipsec_sa_create(int outbound, int tunnel, uint32_t spi,
		const uint8_t* key, uint32_t key_len, uint32_t replay_win, int esn, uint64_t seq_start,
		uint32_t src_ip, uint32_t dst_ip, const uint8_t* src_mac, const uint8_t* dst_mac, int socket);
	uint64_t mg_ipsec_sa_next_seq(const struct mg_ipsec_sa* s);
	void mg_ipsec_sa_destroy(struct mg_ipsec_sa* s);
	uint64_t mg_ipsec_sa_rx_range(const struct mg_ipsec_sa* s, uint64_t* first, uint64_t* last);
	uint16_t mg_ipsec_encrypt_burst(struct mg_ipsec_sa* s, struct rte_mbuf** mb, uint16_t n,
		const uint8_t* tmpl, uint16_t tmpl_len, uint64_t* seq, uint64_t* fails,
		uint32_t t0, uint64_t step, uint16_t group, uint32_t t_min);
	void mg_payload_times(struct rte_mbuf** mb, uint16_t n, uint32_t t0, uint64_t step, uint16_t group, uint32_t t_min);
	void mg_fill_mix(struct rte_mbuf** mb, uint16_t n, const uint8_t* const* tmpls, const uint16_t* lens, uint16_t plen,
		uint16_t* pos, uint64_t* seq);
	uint16_t mg_ipsec_decrypt_burst(struct mg_ipsec_sa* s, struct rte_mbuf** mb, uint16_t n, uint16_t* prep_ok);

	struct mg_flow {
		uint64_t rx;
		uint64_t lost;
		uint64_t late;
		uint64_t exp;
	};
	struct mg_flows {
		uint64_t other;
		struct mg_flow f[4096]; // = MG_FLOWS_MAX in src/ipsec-sw.c, both must be the same
	};

	struct mg_lat {
		uint64_t n;
		uint64_t sum;
		uint64_t max;
		uint64_t untimed;
		uint64_t neg;
		uint64_t ipdv_sum;
		uint64_t ipdv_n;
		uint32_t last[4096];  // = MG_FLOWS_MAX
		uint64_t h[22528];    // = MG_LAT_BUCKETS = (32 - MG_LAT_SUB) << MG_LAT_SUB with MG_LAT_SUB = 10
	};

	uint16_t mg_ipsec_rx_decrypt(uint16_t port, uint16_t queue, struct rte_mbuf** mb, uint16_t burst,
		struct mg_ipsec_sa** sas, uint32_t nb_sa, uint32_t spi_base, struct mg_ipsec_rx_stats* st, struct mg_flows* fl,
		uint16_t l3_off, struct mg_lat* lat);
	uint16_t mg_plain_rx(uint16_t port, uint16_t queue, struct rte_mbuf** mb, uint16_t burst, struct mg_flows* fl,
		struct mg_lat* lat);
]]

local mod = {}

-- crypto vdev of the DPDK config (examples/ipsec/dpdk-conf.lua)
mod.defaultCryptoDev = "crypto_aesni_gcm0"

--- Initialize the crypto device. Call once in master() before starting tasks.
--- @param maxSessions number of SAs that will be created in total (all tasks); the session pool gets 16 more as reserve
--- @param cryptoDev name of the crypto vdev, default crypto_aesni_gcm0
function mod.init(maxSessions, cryptoDev, socket)
	cryptoDev = cryptoDev or mod.defaultCryptoDev
	local id = C.mg_ipsec_init(cryptoDev, (maxSessions or 1024) + 16, socket or 0)
	if id < 0 then
		log:fatal("Could not initialize IPsec crypto device %s", cryptoDev)
	end
	return id
end

--- Convert a hex key (AES key followed by 4 byte salt, RFC 4106) to a byte buffer.
--- @return buffer, AES key length in bytes (16 or 32)
function mod.parseKey(hex)
	hex = hex:gsub("^0x", "")
	local len = #hex / 2
	if len ~= 20 and len ~= 36 then
		log:fatal("IPsec key must be 16 or 32 bytes AES key + 4 bytes salt (40 or 72 hex chars), got %d bytes", len)
	end
	-- two hex digits per byte
	local buf = ffi.new("uint8_t[?]", len)
	for i = 0, len - 1 do
		buf[i] = tonumber(hex:sub(2 * i + 1, 2 * i + 2), 16)
	end
	return buf, len - 4
end

--- Fixed, well-known test keys (never use for anything real).
function mod.testKey(bits)
	local key = bits == 128 and ("00112233445566778899aabbccddeeff") or ("00112233445566778899aabbccddeeff" .. "0123456789abcdef0123456789abcdef")
	return key .. "cafebabe"
end

-- accepts "a.b.c.d" or a number as returned by parseIP4Address (possibly negative, bit ops are signed)
local function ip4(str)
	local ip = type(str) == "number" and str or parseIP4Address(str)
	if not ip then
		log:fatal("Invalid IPv4 address %s", tostring(str))
	end
	-- negative: the same address as unsigned 32-bit number
	if ip < 0 then
		ip = ip + 2^32
	end
	return ip
end

-- MAC address string as byte array, nil stays nil (no MAC given)
local function mac(str)
	if not str then
		return nil
	end
	local addr = parseMacAddress(str)
	if not addr then
		log:fatal("Invalid MAC address %s", str)
	end
	-- own array, a reference to addr.uint8 would not keep addr alive
	local bytes = ffi.new("uint8_t[6]")
	ffi.copy(bytes, addr.uint8, 6)
	return bytes
end

--- Create a security association.
--- @param args table:
---   dir         "out" (encrypt) or "in" (decrypt)
---   mode        "tunnel" (default, outer IPv4 header) or "transport"
---   spi         SPI (number)
---   key         hex string, AES key + 4 byte salt, see parseKey
---   src, dst    outer IPv4 addresses (tunnel mode)
---   srcMac, dstMac  Ethernet addresses of the encrypted frames (outbound tunnel mode)
---   replayWindow    anti-replay window size for inbound SAs (default 64, 0 disables)
---   esn         true: extended (64 bit) sequence numbers
---   seqStart    sequence number to continue from (mod.loadSeqFile): outbound the first one sent, inbound the
---               highest one received so far (top of the replay window); default: from the start
function mod.createSa(args)
	local outbound = args.dir == "out"
	local tunnel = (args.mode or "tunnel") == "tunnel"
	local key, keyLen = mod.parseKey(args.key)
	local srcMac, dstMac = mac(args.srcMac), mac(args.dstMac)
	-- the outer addresses only count in tunnel mode
	local sa = C.mg_ipsec_sa_create(outbound and 1 or 0, tunnel and 1 or 0, args.spi,
		key, keyLen, args.replayWindow or 64, args.esn and 1 or 0, args.seqStart or 0,
		tunnel and ip4(args.src) or 0, tunnel and ip4(args.dst) or 0,
		srcMac, dstMac, args.socket or 0)
	if sa == nil then
		log:fatal("Could not create IPsec SA with SPI %d", args.spi)
	end
	return sa
end

--- Encrypt bufs[0..n-1] in place, optionally re-filling them from a packet template first.
--- @param seq optional uint64_t[1]: the template holds the generator payload (mod.fillPayload) and every packet
---   gets the next sequence number from seq[0]
--- @param times optional send times (mod.sendTimes), written into the payload before the encryption
--- @return number of encrypted packets at the start of bufs.array (failed ones are freed)
function mod.encrypt(sa, bufs, n, tmpl, tmplLen, fails, seq, times)
	if times then
		return C.mg_ipsec_encrypt_burst(sa, bufs.array, n, tmpl, tmplLen or 0, seq, fails, times[1], times[2], times[3],
			times[4])
	end
	return C.mg_ipsec_encrypt_burst(sa, bufs.array, n, tmpl, tmplLen or 0, seq, fails, 0, 0, 0, 0)
end

--- Payload of the generated packets, the UDP payload of the (inner) packet with and without ESP, so that
--- either receiver checks the traffic of either generator, also after a device in between has en- or decrypted it:
--- magic (uint32) | send time (uint32, 0 = none, see mod.sendTimes) | sequence number of the flow (uint64) |
--- flow (uint16) = 18 bytes, which fills a 60 byte frame (see struct mg_payload in src/ipsec-sw.c).
-- magic = "PLAI"
mod.PAYLOAD_MAGIC = 0x504c4149
mod.MIN_FRAME = 60
mod.MAX_FLOWS = 4096

--- Write the constant part of the payload (all but the sequence number) into a UDP packet.
function mod.fillPayload(udpPkt, flow)
	-- magic and send time as uint32 0 and 1, the flow as uint16 8 (bytes 16-17)
	local p = udpPkt.payload
	p.uint32[0], p.uint32[1], p.uint16[8] = mod.PAYLOAD_MAGIC, 0, flow
end

--- Write the sequence number into the payload of a UDP packet.
function mod.setPayloadSeq(udpPkt, seq)
	-- uint64 1 = bytes 8-15
	udpPkt.payload.uint64[1] = seq
end

--- Packet size mix of the generators for "-s imix": the 7 : 4 : 1 mix of FD.io CSIT (64, 570, 1518 bytes with CRC),
--- but with 1460 instead of 1514 bytes as the largest frame (sizes without CRC), the largest cleartext frame whose
--- ESP frame in tunnel mode (1514 bytes, no padding) still fits the MTU of 1500 bytes; spread evenly over a pattern
--- of 12 packets. Mean 345.3 bytes as cleartext, 400 bytes as ESP frame (114, 622, 1514).
mod.IMIX = { 60, 566, 60, 60, 566, 60, 1460, 60, 566, 60, 60, 566 }

--- The packet sizes of the value of a generator's size option: { n } for a number n, mod.IMIX for "imix".
function mod.sizes(s)
	if s == "imix" then return mod.IMIX end
	-- a number: one size, at least the minimum frame for the payload
	local n = tonumber(s)
	if not n or n < mod.MIN_FRAME then log:fatal("Packet size must be at least %d (generator payload) or imix", mod.MIN_FRAME) end
	return { n }
end

--- Packet template of len bytes: fill(buf, len) fills the first buffer of bufs, which is then copied.
function mod.template(bufs, len, fill)
	bufs:alloc(len)
	-- fill the first buffer, copy it into the template and give the buffers back
	fill(bufs[1], len)
	local t = ffi.new("uint8_t[?]", len)
	ffi.copy(t, bufs[1]:getData(), len)
	bufs:freeAll()
	return t
end

--- Templates of a size pattern (mod.sizes) for mod.fillMix, one per distinct size (see mod.template).
function mod.mixTemplates(sizes, bufs, fill)
	local mix = { n = #sizes, ptrs = ffi.new("const uint8_t*[?]", #sizes), lens = ffi.new("uint16_t[?]", #sizes), bySize = {} }
	-- one template per distinct size, shared by all positions of the pattern with that size
	for i, len in ipairs(sizes) do
		mix.bySize[len] = mix.bySize[len] or mod.template(bufs, len, fill)
		mix.ptrs[i - 1], mix.lens[i - 1] = mix.bySize[len], len
	end
	return mix
end

--- Fill bufs[0..n-1] from the templates of mod.mixTemplates in the order of the pattern, which continues from pos[0]
--- (uint16_t[1]); every packet gets the next sequence number from seq[0] (uint64_t[1]).
function mod.fillMix(bufs, n, mix, pos, seq)
	C.mg_fill_mix(bufs.array, n, mix.ptrs, mix.lens, mix.n, pos, seq)
end

--- Per-flow state of one receive queue for mod.rxDecrypt and mod.plainRx.
function mod.newFlows()
	return ffi.new("struct mg_flows")
end

--- The flows seen by one receive queue as a plain table (to be returned by a task).
--- @return { other = n, flows = { [id] = { rx, lost, late } } }
function mod.flowResults(fl)
	local res = { other = tonumber(fl.other), flows = {} }
	-- only the flows seen on this queue
	for id = 0, mod.MAX_FLOWS - 1 do
		local f = fl.f[id]
		if f.rx > 0 then
			res.flows[id] = { rx = tonumber(f.rx), lost = tonumber(f.lost), late = tonumber(f.late) }
		end
	end
	return res
end

--- Merge and print the flow results of all receive queues (res[q] = mod.flowResults of queue q):
--- one line per flow with the queue(s) it arrived on and one line with the totals, both starting with prefix.
--- @return totals { flows, rx, lost, late, split, other }
function mod.flowSummary(res, queues, prefix)
	-- merge the flows of all queues; ids lists every flow once, sorted below
	local flows, ids, other = {}, {}, 0
	for q = 0, queues - 1 do
		other = other + res[q].other
		for id, f in pairs(res[q].flows) do
			if not flows[id] then
				flows[id], ids[#ids + 1] = { rx = 0, lost = 0, late = 0, queues = {} }, id
			end
			local e = flows[id]
			e.rx, e.lost, e.late = e.rx + f.rx, e.lost + f.lost, e.late + f.late
			e.queues[#e.queues + 1] = q
		end
	end
	table.sort(ids)
	-- one line per flow, summed up in total; split = flows that arrived on more than one queue
	local total = { flows = #ids, rx = 0, lost = 0, late = 0, split = 0, other = other }
	for _, id in ipairs(ids) do
		local e = flows[id]
		log:info("%sFlow %d: received %d, missing %d, late/duplicate %d, queue(s) %s", prefix, id, e.rx, e.lost, e.late, table.concat(e.queues, ","))
		total.rx, total.lost, total.late = total.rx + e.rx, total.lost + e.lost, total.late + e.late
		if #e.queues > 1 then total.split = total.split + 1 end
	end
	log:info("%sTotal: flows %d, received %d, missing %d, late/duplicate %d, flows on more than one queue %d, other packets %d",
		prefix, total.flows, total.rx, total.lost, total.late, total.split, total.other)
	return total
end

--- Read a list of SAs that were set up elsewhere, e.g. negotiated by an IKE daemon.
--- One SA per line: direction ("out" = to be sent, "in" = to be received), SPI, key (hex, AES key + 4 byte
--- salt), outer source and destination address and optionally the inner source and destination address the
--- SA is meant for, and "esn" as last word if it uses extended sequence numbers; "#" starts a comment.
--- The same file serves a generator, a sink and a transceiver.
--- @param dir "out" or "in": the SAs of the other direction are skipped
--- @return list of { spi, key, src, dst, innerSrc, innerDst, esn }
function mod.loadSaFile(path, dir)
	local file = io.open(path)
	if not file then
		log:fatal("Could not open SA file %s", path)
	end
	local list = {}
	-- per line: its words without the comment
	for line in file:lines() do
		local f = {}
		for word in line:gsub("#.*", ""):gmatch("%S+") do
			f[#f + 1] = word
		end
		-- "esn" as last word: flag of the SA, not an address
		local esn = f[#f] == "esn"
		if esn then
			f[#f] = nil
		end
		-- an SA line (direction, numeric SPI, key and both outer addresses) is kept if it has the requested direction;
		-- any other line that is not empty after removing the comment is an error
		if #f >= 5 and (f[1] == "out" or f[1] == "in") and tonumber(f[2]) then
			if f[1] == dir then
				list[#list + 1] = { spi = tonumber(f[2]), key = f[3], src = f[4], dst = f[5], innerSrc = f[6], innerDst = f[7], esn = esn }
			end
		elseif #f > 0 then
			log:fatal("Invalid line in SA file %s: %s", path, line)
		end
	end
	file:close()
	if #list == 0 then
		log:fatal("No \"%s\" SAs in SA file %s", dir, path)
	end
	return list
end

--- Sequence numbers to continue on SAs that a peer keeps across runs (a DUT that negotiated them by IKE), one line per
--- SA: "out SPI NEXT" = the number the next packet sent on the outbound SA gets, "in SPI LAST" = the highest number
--- received on the inbound SA (top of its replay window, from which the upper 32 bits of extended sequence numbers
--- are inferred). A missing file or SA means: from the start.
--- @return table { out = { [SPI as string] = NEXT }, ["in"] = { [SPI as string] = LAST } }
function mod.loadSeqFile(path)
	local seqs = { out = {}, ["in"] = {} }
	local file = io.open(path)
	if not file then return seqs end
	-- lines "out|in SPI N"; other lines are skipped
	for line in file:lines() do
		local dir, spi, n = line:match("^%s*(%a+)%s+(%d+)%s+(%d+)")
		if seqs[dir] then seqs[dir][spi] = tonumber(n) end
	end
	file:close()
	return seqs
end

--- Merge the lines "out SPI NEXT" / "in SPI LAST" (from mod.nextSeqs and mod.lastSeqs) into the sequence file: the
--- transmit and the receive tasks write their own SAs, the entries of the others stay.
function mod.saveSeqFile(path, lines)
	-- the entries of the file, overwritten by the lines of the caller
	local seqs = mod.loadSeqFile(path)
	for dir, spi, n in lines:gmatch("(%a+) (%d+) (%d+)") do
		seqs[dir][spi] = tonumber(n)
	end
	local file = io.open(path, "w")
	if not file then log:fatal("Could not write sequence file %s", path) end
	-- the whole file again, out before in
	for _, dir in ipairs({ "out", "in" }) do
		for spi, n in pairs(seqs[dir]) do
			file:write(("%s %s %d\n"):format(dir, spi, n))
		end
	end
	file:close()
end

--- "out SPI NEXT" lines of the outbound SAs sas[1..n] with their SPIs spis[1..n], for mod.saveSeqFile.
function mod.nextSeqs(sas, spis)
	local t = {}
	for j = 1, #sas do
		t[j] = ("out %d %d\n"):format(spis[j], tonumber(C.mg_ipsec_sa_next_seq(sas[j])))
	end
	return table.concat(t)
end

--- "in SPI LAST" lines of the inbound SAs sas[1..n] that received packets, for mod.saveSeqFile.
function mod.lastSeqs(sas, spis)
	local t = {}
	for j = 1, #sas do
		local seen, _, last = mod.rxRange(sas[j])
		if seen > 0 then t[#t + 1] = ("in %d %d\n"):format(spis[j], last) end
	end
	return table.concat(t)
end

--- Create an SA lookup table indexed by SPI - spiBase for mod.rxDecrypt.
function mod.createSaTable(sas)
	local tbl = ffi.new("struct mg_ipsec_sa*[?]", #sas)
	for i, sa in ipairs(sas) do
		tbl[i - 1] = sa
	end
	return tbl
end

--- Create an SA lookup table for arbitrary SPIs for mod.rxDecrypt (to be called with spiBase = 0):
--- a hash table indexed by the low bits of the SPI with linear probing, at most half full.
--- @param spis the SPIs of the SAs, in the same order
--- @return table, number of slots (= numSas of mod.rxDecrypt)
function mod.createSpiTable(sas, spis)
	-- the smallest power of two that is at least twice the number of SAs
	local slots = 2
	while slots < 2 * #sas do
		slots = slots * 2
	end
	local tbl = ffi.new("struct mg_ipsec_sa*[?]", slots)
	-- each SA in the first free slot from the low bits of its SPI on
	for i, sa in ipairs(sas) do
		local slot = bit.band(spis[i], slots - 1)
		while tbl[slot] ~= nil do
			slot = bit.band(slot + 1, slots - 1)
		end
		tbl[slot] = sa
	end
	return tbl, slots
end

-- One rte_flow rule in the NIC: IPv4 packets matching the optional IPv4 and ESP items go to rxQueue.
local function steer(rxQueue, what, ip, esp)
	local attr = ffi.new("struct rte_flow_attr", { ingress = 1 })
	-- pattern ETH / IPV4 (with ip) / ESP (with esp) / END; without esp the pattern ends after IPV4
	local items = ffi.new("struct rte_flow_item[4]")
	items[0].type = C.RTE_FLOW_ITEM_TYPE_ETH
	items[1].type = C.RTE_FLOW_ITEM_TYPE_IPV4
	if ip then items[1].spec, items[1].mask = ip[1], ip[2] end
	items[2].type = esp and C.RTE_FLOW_ITEM_TYPE_ESP or C.RTE_FLOW_ITEM_TYPE_END
	if esp then items[2].spec, items[2].mask = esp[1], esp[2] end
	items[3].type = C.RTE_FLOW_ITEM_TYPE_END
	-- action: to the queue, then END
	local queue = ffi.new("struct rte_flow_action_queue", { index = rxQueue.qid })
	local actions = ffi.new("struct rte_flow_action[2]")
	actions[0].type, actions[0].conf = C.RTE_FLOW_ACTION_TYPE_QUEUE, queue
	actions[1].type = C.RTE_FLOW_ACTION_TYPE_END
	local err = ffi.new("struct rte_flow_error")
	if C.rte_flow_create(rxQueue.id, attr, items, actions, err) == nil then
		log:fatal("Could not steer %s to queue %d: %s", what, rxQueue.qid, err.message ~= nil and ffi.string(err.message) or "unknown error")
	end
end

--- Flow isolation: the port only receives what an rte_flow rule (steerSpi, steerSrcIp) sends to one of its queues.
--- Everything else stays with the kernel driver of the port, which thereby keeps answering ARP and receiving IKE
--- while this application runs; without isolation the application takes all frames of the port and drops those.
--- Works with bifurcated drivers (mlx5); to be called before device.config.
function mod.isolate(port)
	local err = ffi.new("struct rte_flow_error")
	if C.rte_flow_isolate(port, 1, err) ~= 0 then
		log:fatal("Could not isolate port %d: %s", port, err.message ~= nil and ffi.string(err.message) or "unknown error")
	end
end

--- Steer all ESP packets with the given SPI to one RX queue (rte_flow rule in the NIC).
--- Unlike RSS this does not depend on the IP addresses, so every SA gets a defined core.
function mod.steerSpi(rxQueue, spi)
	local spec, mask = ffi.new("struct rte_flow_item_esp"), ffi.new("struct rte_flow_item_esp")
	-- network byte order
	spec.hdr.spi = bit.bswap(spi) % 2^32
	mask.hdr.spi = 0xffffffff
	steer(rxQueue, "SPI " .. spi, nil, { spec, mask })
end

--- Steer all IPv4 packets with the given source address to one RX queue (for the cleartext flows).
function mod.steerSrcIp(rxQueue, ip)
	local spec, mask = ffi.new("struct rte_flow_item_ipv4"), ffi.new("struct rte_flow_item_ipv4")
	-- network byte order
	spec.hdr.src_addr = bit.bswap(ip4(ip)) % 2^32
	mask.hdr.src_addr = 0xffffffff
	steer(rxQueue, "source IP " .. tostring(ip), { spec, mask })
end

--- First and last ESP sequence number mod.rxDecrypt received for this SA, extended to 64 bits across wraps.
--- @return number of packets received, first sequence number, last sequence number
function mod.rxRange(sa)
	local range = ffi.new("uint64_t[2]")
	local seen = tonumber(C.mg_ipsec_sa_rx_range(sa, range, range + 1))
	return seen, tonumber(range[0]), tonumber(range[1])
end

--- Receive counters of one queue for mod.rxDecrypt (struct mg_ipsec_rx_stats).
function mod.newRxStats()
	return ffi.new("struct mg_ipsec_rx_stats")
end

-- length of the Ethernet header, offset of the inner IPv4 header in transport mode
local ETH_HDR_LEN = 14
--- Receive, decrypt, count and free one burst; with flows (mod.newFlows) also check the payload of the decrypted
--- packets, whose inner IPv4 header starts at offset 0 in tunnel mode and after the Ethernet header in transport mode;
--- with lat (mod.newLatency) also their latency.
function mod.rxDecrypt(rxQueue, bufs, saTable, numSas, spiBase, stats, flows, mode, lat)
	return C.mg_ipsec_rx_decrypt(rxQueue.id, rxQueue.qid, bufs.array, bufs.size, saTable, numSas, spiBase, stats, flows,
		mode == "transport" and ETH_HDR_LEN or 0, lat)
end

--- Receive one burst of cleartext packets, check their payload into flows (mod.newFlows), with lat (mod.newLatency)
--- also their latency, and free them.
function mod.plainRx(rxQueue, bufs, flows, lat)
	return C.mg_plain_rx(rxQueue.id, rxQueue.qid, bufs.array, bufs.size, flows, lat)
end

-- Latency (--latency of the generators, receivers and transceivers): the sender writes the time at which a packet
-- leaves into the send time field of its payload, as the low 32 bits of the TSC (see struct mg_payload in
-- src/ipsec-sw.c for why TSC ticks); the receiver subtracts it from the TSC at its rx burst and counts the result per
-- queue in a histogram (struct mg_lat). Only meaningful if sender and receiver share the TSC, i.e. run on one node.
-- With NIC pacing the time is the one in the schedule at which the NIC sends the packet, or the time at which the
-- burst is filled if the sender is behind its schedule (then the NIC sends at once); the pacer maps the schedule to
-- the NIC clock (pacer:calibrate), so the error of that mapping is in the result, and a burst whose encryption takes
-- longer than the lead leaves late, which shows up as latency. Without pacing it is the time at which the burst is
-- filled, before its encryption. The sender writes no times during its ramp (time 0), so that only the full rate is
-- measured.

-- TSC ticks per second of this process, and libmoon for the TSC time
local tscHz
local libmoon = require "libmoon"

--- Send times of a burst for mod.encrypt and mod.stampTimes, written into times = { t0, step, group, tMin } (one table
--- per task, reused for every burst): due = time (mg.getTime) of its first packet in the schedule, spacing = seconds
--- between its packets (0 without pacing), group = pacing group; no packet gets a time before now (mg.getTime), see
--- mg_payload_times in src/ipsec-sw.c. Returns times.
function mod.sendTimes(times, due, spacing, group)
	tscHz = tscHz or libmoon.getCyclesFrequency()
	-- low 32 bits of the TSC at due and now, and the spacing in ticks with 16 fractional bits; the products stay below
	-- 2^53
	times[1], times[2], times[3] = due * tscHz % 2^32, spacing * tscHz * 65536, group or 1
	times[4] = libmoon.getTime() * tscHz % 2^32
	return times
end

--- Write send times (mod.sendTimes) into the payload of bufs[0..n-1], for packets that are not encrypted.
function mod.stampTimes(bufs, n, times)
	C.mg_payload_times(bufs.array, n, times[1], times[2], times[3], times[4])
end

--- Latency histogram of one receive queue for mod.rxDecrypt and mod.plainRx.
function mod.newLatency()
	return ffi.new("struct mg_lat")
end

--- The latency counters of one receive queue as a plain table (to be returned by a task), the histogram only with
--- its buckets that are not empty.
--- @return { n, sum, max, untimed, neg, ipdvSum, ipdvN, h = { [bucket] = count } }
function mod.latencyResults(lat)
	local res = { n = tonumber(lat.n), sum = tonumber(lat.sum), max = tonumber(lat.max),
		untimed = tonumber(lat.untimed), neg = tonumber(lat.neg), ipdvSum = tonumber(lat.ipdv_sum),
		ipdvN = tonumber(lat.ipdv_n), h = {} }
	-- only the buckets that are not empty (22528 = size of h in the declaration above)
	for i = 0, 22528 - 1 do
		if lat.h[i] > 0 then res.h[i] = tonumber(lat.h[i]) end
	end
	return res
end

-- histogram buckets per power of two = 2^MG_LAT_SUB in src/ipsec-sw.c
local LAT_SUB = 1024
-- middle of histogram bucket i in TSC ticks: below LAT_SUB one tick per bucket, above LAT_SUB buckets per power of two
local function bucketMid(i)
	if i < LAT_SUB then return i end
	-- bucket i covers (LAT_SUB + i % LAT_SUB) * 2^shift up to the next bucket
	local shift = math.floor(i / LAT_SUB) - 1
	return (LAT_SUB + i % LAT_SUB) * 2^shift + (2^shift - 1) / 2
end

--- Merge and print the latency of all receive queues (res[q] = mod.latencyResults of queue q): one line
--- "<prefix>Latency: n=... min=... p1=... p50=... p90=... p99=... p999=... max=... mean=... ipdv=... untimed=...
--- neg=... (us)" with the times in microseconds (percentiles at the middle of their histogram bucket, resolution
--- 0.1 %), n = packets with a send time, ipdv = mean |difference| of consecutive packets of a flow (RFC 3393).
--- @return the line without the prefix, nil if no packet had a send time
function mod.latencySummary(res, queues, prefix)
	tscHz = tscHz or libmoon.getCyclesFrequency()
	-- the counters and the histograms of all queues added up
	local t, h = { n = 0, sum = 0, max = 0, untimed = 0, neg = 0, ipdvSum = 0, ipdvN = 0 }, {}
	for q = 0, queues - 1 do
		local r = res[q]
		for _, k in ipairs({ "n", "sum", "untimed", "neg", "ipdvSum", "ipdvN" }) do
			t[k] = t[k] + r[k]
		end
		t.max = math.max(t.max, r.max)
		for i, c in pairs(r.h) do
			h[i] = (h[i] or 0) + c
		end
	end
	-- no packet with a send time: the sender ran without --latency
	if t.n == 0 then
		log:info("%sLatency: no packets with a send time (untimed %d, negative %d)", prefix, t.untimed, t.neg)
		return nil
	end
	-- the buckets in ascending order; for each percentile the first bucket at which the cumulated count reaches it
	local idx = {}
	for i in pairs(h) do idx[#idx + 1] = i end
	table.sort(idx)
	local us = function(ticks) return ticks / tscHz * 1e6 end
	local qs, pct, k, cum = { 0.01, 0.5, 0.9, 0.99, 0.999 }, {}, 1, 0
	for _, i in ipairs(idx) do
		cum = cum + h[i]
		-- this bucket may hold several percentiles
		while k <= #qs and cum >= qs[k] * t.n do
			pct[k], k = us(bucketMid(i)), k + 1
		end
	end
	local line = ("Latency: n=%d min=%.3f p1=%.3f p50=%.3f p90=%.3f p99=%.3f p999=%.3f max=%.3f mean=%.3f ipdv=%.3f"
		.. " untimed=%d neg=%d (us)"):format(t.n, us(bucketMid(idx[1])), pct[1], pct[2], pct[3], pct[4], pct[5],
			us(t.max), us(t.sum / t.n), t.ipdvN > 0 and us(t.ipdvSum / t.ipdvN) or 0, t.untimed, t.neg)
	log:info("%s%s", prefix, line)
	return line
end

-- NIC pacing (--nic-pacing of the generators): the NIC sends every packet at the time it carries in its mbuf
-- (send on timestamp, device.config with sendOnTimestamp = true), on the PTP clock of the NIC (kernel PHC).
-- The transmit loop hands each burst over a lead time ahead of its time in the schedule, and the packets of the
-- burst get times spaced evenly over the interval up to the next burst; the NIC thereby interleaves the packets of
-- all transmit queues instead of sending each burst back to back at line rate.
-- in a pcall: another module may have declared these already, and a second declaration fails
pcall(ffi.cdef, [[
	int open(const char* pathname, int flags);
	int rte_eth_dev_get_name_by_port(uint16_t port_id, char* name);
]])
-- clock_gettime
require "utils"

--- Device file of the PTP clock of a DPDK port (PCI devices only), e.g. /dev/ptp5; to be called in the master.
function mod.ptpClock(port)
	-- the PCI device of the port lists its PTP clock under ptp/ in sysfs
	local name = ffi.new("char[64]")
	if C.rte_eth_dev_get_name_by_port(port, name) ~= 0 then return nil end
	local ls = io.popen("ls /sys/bus/pci/devices/" .. ffi.string(name) .. "/ptp 2>/dev/null")
	local ptp = ls:read("*l")
	ls:close()
	return ptp and "/dev/" .. ptp
end

-- methods of the objects of mod.newPacer
local pacer = {}
pacer.__index = pacer

--- Per transmit task: clock = mod.ptpClock of the port, lead in seconds; with group > 1 only every group-th packet
--- carries a time and the ones in between follow it back to back (the NIC needs an extra work request per time).
function mod.newPacer(clock, lead, group)
	local dpdkc = require "dpdkc"
	-- the PTP clock opened read-only, -1 without one
	local fd = clock and C.open(clock, 0) or -1
	local self = setmetatable({
		-- mbuf field and flag of the send time, registered by libmoon's device.config with sendOnTimestamp
		off = dpdkc.dpdk_tx_timestamp_offset(),
		flag = dpdkc.dpdk_tx_timestamp_flag(),
		lead = lead,
		group = group or 1,
		-- clock id of the opened PTP clock for clock_gettime: FD_TO_CLOCKID(fd) = (~fd << 3) | 3 of the Linux kernel
		clk = bit.bor(bit.lshift(bit.bnot(fd), 3), 3),
		ts = ffi.new("struct timespec"),
		getTime = require("moongen").getTime,
	}, pacer)
	if self.off < 0 or fd < 0 then
		log:fatal("NIC pacing needs a device configured with sendOnTimestamp and its PTP clock (%s)", tostring(clock))
	end
	-- the first pair of times
	self:calibrate()
	return self
end

--- Pair of mg.getTime (s) and NIC clock (ns, uint64) from the shortest of five reads (a read takes about 1.5 us).
function pacer:calibrate()
	-- the NIC clock read between two reads of mg.getTime; the shortest span gives the best pair, with the NIC time
	-- taken at the middle of the span
	local best = math.huge
	for _ = 1, 5 do
		local t0 = self.getTime()
		C.clock_gettime(self.clk, self.ts)
		local t1 = self.getTime()
		if t1 - t0 < best then
			best = t1 - t0
			self.t = (t0 + t1) / 2
			self.ns = ffi.cast("uint64_t", self.ts.tv_sec) * 1000000000ULL + self.ts.tv_nsec
		end
	end
	-- TSC and NIC clock drift apart by some ppm: calibrate again after 100 ms
	self.nextCal = self.t + 0.1
end

--- Send times for the first n packets of bufs: due (mg.getTime) for the first one, then every spacing seconds.
function pacer:stamp(bufs, n, due, spacing)
	if due > self.nextCal then self:calibrate() end
	-- base and step in ns from the calibration point; every group-th packet gets its send time and the flag
	local base, step = (due - self.t) * 1e9, spacing * 1e9
	for i = 0, n - 1, self.group do
		local m = bufs.array[i]
		ffi.cast("uint64_t*", ffi.cast("uint8_t*", m) + self.off)[0] = self.ns + ffi.cast("int64_t", base + i * step)
		m.ol_flags = bit.bor(m.ol_flags, self.flag)
	end
end

return mod
