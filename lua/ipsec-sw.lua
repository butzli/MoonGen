---------------------------------
--- @file ipsec-sw.lua
--- @brief Software IPsec (ESP, AES-GCM) based on DPDK rte_ipsec + CPU crypto (ipsec_mb).
--- Requires the crypto vdev in the DPDK config, e.g. cli = { "--vdev=crypto_aesni_gcm0" },
--- and DPDK built with libipsec-mb-dev installed.
---------------------------------

local ffi = require "ffi"
local log = require "log"
require "filter" -- rte_flow declarations

local C = ffi.C

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
		const uint8_t* key, uint32_t key_len, uint32_t replay_win, int esn,
		uint32_t src_ip, uint32_t dst_ip, const uint8_t* src_mac, const uint8_t* dst_mac, int socket);
	void mg_ipsec_sa_destroy(struct mg_ipsec_sa* s);
	uint64_t mg_ipsec_sa_rx_range(const struct mg_ipsec_sa* s, uint32_t* first, uint32_t* last);
	uint16_t mg_ipsec_encrypt_burst(struct mg_ipsec_sa* s, struct rte_mbuf** mb, uint16_t n,
		const uint8_t* tmpl, uint16_t tmpl_len, uint64_t* fails);
	uint16_t mg_ipsec_decrypt_burst(struct mg_ipsec_sa* s, struct rte_mbuf** mb, uint16_t n, uint16_t* prep_ok);
	uint16_t mg_ipsec_rx_decrypt(uint16_t port, uint16_t queue, struct rte_mbuf** mb, uint16_t burst,
		struct mg_ipsec_sa** sas, uint32_t nb_sa, uint32_t spi_base, struct mg_ipsec_rx_stats* st);
]]

local mod = {}

mod.defaultCryptoDev = "crypto_aesni_gcm0"

--- Initialize the crypto device. Call once in master() before starting tasks.
--- @param maxSessions number of SAs that will be created in total (all tasks)
--- @param cryptoDev name of the crypto vdev, default crypto_aesni_gcm0
function mod.init(maxSessions, cryptoDev, socket)
	cryptoDev = cryptoDev or mod.defaultCryptoDev
	local id = C.mg_ipsec_init(cryptoDev, maxSessions or 1024, socket or 0)
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
	if ip < 0 then
		ip = ip + 2^32
	end
	return ip
end

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
function mod.createSa(args)
	local outbound = args.dir == "out"
	local tunnel = (args.mode or "tunnel") == "tunnel"
	local key, keyLen = mod.parseKey(args.key)
	local srcMac, dstMac = mac(args.srcMac), mac(args.dstMac)
	local sa = C.mg_ipsec_sa_create(outbound and 1 or 0, tunnel and 1 or 0, args.spi,
		key, keyLen, args.replayWindow or 64, args.esn and 1 or 0,
		tunnel and ip4(args.src) or 0, tunnel and ip4(args.dst) or 0,
		srcMac, dstMac, args.socket or 0)
	if sa == nil then
		log:fatal("Could not create IPsec SA with SPI %d", args.spi)
	end
	return sa
end

--- Encrypt bufs[0..n-1] in place, optionally re-filling them from a packet template first.
--- @return number of encrypted packets at the start of bufs.array (failed ones are freed)
function mod.encrypt(sa, bufs, n, tmpl, tmplLen, fails)
	return C.mg_ipsec_encrypt_burst(sa, bufs.array, n, tmpl, tmplLen or 0, fails)
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
	for line in file:lines() do
		local f = {}
		for word in line:gsub("#.*", ""):gmatch("%S+") do
			f[#f + 1] = word
		end
		local esn = f[#f] == "esn"
		if esn then
			f[#f] = nil
		end
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
	local slots = 2
	while slots < 2 * #sas do
		slots = slots * 2
	end
	local tbl = ffi.new("struct mg_ipsec_sa*[?]", slots)
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
	local items = ffi.new("struct rte_flow_item[4]")
	items[0].type = C.RTE_FLOW_ITEM_TYPE_ETH
	items[1].type = C.RTE_FLOW_ITEM_TYPE_IPV4
	if ip then items[1].spec, items[1].mask = ip[1], ip[2] end
	items[2].type = esp and C.RTE_FLOW_ITEM_TYPE_ESP or C.RTE_FLOW_ITEM_TYPE_END
	if esp then items[2].spec, items[2].mask = esp[1], esp[2] end
	items[3].type = C.RTE_FLOW_ITEM_TYPE_END
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
	spec.hdr.spi = bit.bswap(spi) % 2^32 -- network byte order
	mask.hdr.spi = 0xffffffff
	steer(rxQueue, "SPI " .. spi, nil, { spec, mask })
end

--- Steer all IPv4 packets with the given source address to one RX queue (for the cleartext flows).
function mod.steerSrcIp(rxQueue, ip)
	local spec, mask = ffi.new("struct rte_flow_item_ipv4"), ffi.new("struct rte_flow_item_ipv4")
	spec.hdr.src_addr = bit.bswap(ip4(ip)) % 2^32 -- network byte order
	mask.hdr.src_addr = 0xffffffff
	steer(rxQueue, "source IP " .. tostring(ip), { spec, mask })
end

--- First and last ESP sequence number mod.rxDecrypt received for this SA.
--- @return number of packets received, first sequence number, last sequence number
function mod.rxRange(sa)
	local range = ffi.new("uint32_t[2]")
	local seen = tonumber(C.mg_ipsec_sa_rx_range(sa, range, range + 1))
	return seen, range[0], range[1]
end

function mod.newRxStats()
	return ffi.new("struct mg_ipsec_rx_stats")
end

--- Receive, decrypt, count and free one burst.
function mod.rxDecrypt(rxQueue, bufs, saTable, numSas, spiBase, stats)
	return C.mg_ipsec_rx_decrypt(rxQueue.id, rxQueue.qid, bufs.array, bufs.size, saTable, numSas, spiBase, stats)
end

return mod
