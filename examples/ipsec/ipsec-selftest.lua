--- Functional self test of the software IPsec path, no NIC needed:
--- encrypt -> decrypt round trip, ICV tampering and replay detection, tunnel and transport mode.
--- ./build/MoonGen --dpdk-config=examples/ipsec/dpdk-conf.lua examples/ipsec/ipsec-selftest.lua
local mg     = require "moongen"
local memory = require "memory"
local log    = require "log"
local ffi    = require "ffi"
local ipsec  = require "ipsec-sw"

local N = 32

function configure(parser)
	parser:description("Self test for the software IPsec path (rte_ipsec + CPU crypto).")
	parser:option("-s --size", "Inner packet size."):default(60):convert(tonumber)
end

local failed = 0
local function check(cond, fmt, ...)
	if cond then
		log:info("PASS " .. fmt, ...)
	else
		log:error("FAIL " .. fmt, ...)
		failed = failed + 1
	end
end

local function runMode(mode, bits, size, spi)
	local key = ipsec.testKey(bits)
	local out = ipsec.createSa{dir = "out", mode = mode, spi = spi, key = key, src = "192.168.0.1", dst = "192.168.1.1", srcMac = "02:00:00:00:00:01", dstMac = "02:00:00:00:00:02"}
	local inb = ipsec.createSa{dir = "in", mode = mode, spi = spi, key = key, src = "192.168.0.1", dst = "192.168.1.1", replayWindow = 64}

	local mem = memory.createMemPool{n = 1023, func = function(buf)
		buf:getUdpPacket():fill{ethSrc = "02:00:00:00:00:01", ethDst = "02:00:00:00:00:02", ip4Src = "10.0.0.1", ip4Dst = "10.1.0.1", pktLength = size}
	end}
	local bufs = mem:bufArray(N)
	bufs:alloc(size)
	-- distinct payload per packet, keep plaintext copies for comparison
	local plain = {}
	for i = 0, N - 1 do
		local pkt = bufs[i + 1]:getUdpPacket()
		pkt.ip4:calculateChecksum()
		pkt.udp:setChecksum(0)
		pkt.udp:setSrcPort(i)
		plain[i] = ffi.string(bufs[i + 1]:getData(), size)
	end
	local fails = ffi.new("uint64_t[1]")
	local n = ipsec.encrypt(out, bufs, N, nil, 0, fails)
	check(n == N, "[%s/AES-%d] encrypted %d/%d packets, frame %d -> %d B", mode, bits, n, N, size, bufs.array[0].pkt_len)

	-- keep copies of two encrypted packets for the tamper and replay tests
	local extra = mem:bufArray(2)
	extra:alloc(size)
	for i = 0, 1 do
		local len = bufs.array[i].pkt_len
		ffi.copy(extra[i + 1]:getData(), bufs[i + 1]:getData(), len)
		extra.array[i].pkt_len = len
		extra.array[i].data_len = len
	end

	local prepOk = ffi.new("uint16_t[1]")
	local ok = ffi.C.mg_ipsec_decrypt_burst(inb, bufs.array, N, prepOk)
	check(ok == N, "[%s/AES-%d] decrypted+authenticated %d/%d packets", mode, bits, ok, N)
	-- compare everything from the inner UDP header on (IP header fields may legitimately change)
	local l2 = mode == "tunnel" and 0 or 14
	local match = 0
	for i = 0, ok - 1 do
		local data = ffi.string(bufs[i + 1]:getData(), bufs.array[i].pkt_len)
		if data:sub(l2 + 21) == plain[i]:sub(35) and #data == size - 14 + l2 then
			match = match + 1
		end
	end
	check(match == N, "[%s/AES-%d] %d/%d decrypted packets match the plaintext", mode, bits, match, N)

	-- extra[1]: flip one ciphertext byte of a copy of packet 0 -> replayed SQN; use packet 1 copy for tampering
	local tampered = extra[2]:getData()
	local tlen = extra.array[1].pkt_len
	ffi.cast("uint8_t*", tampered)[tlen - 20] = bit.bxor(ffi.cast("uint8_t*", tampered)[tlen - 20], 0xff)
	-- a fresh inbound SA so that packet 1's SQN is not yet seen
	local inb2 = ipsec.createSa{dir = "in", mode = mode, spi = spi, key = key, src = "192.168.0.1", dst = "192.168.1.1", replayWindow = 64}
	local one = ffi.new("struct rte_mbuf*[1]")
	one[0] = extra.array[1]
	local okT = ffi.C.mg_ipsec_decrypt_burst(inb2, one, 1, prepOk)
	check(okT == 0 and prepOk[0] == 1, "[%s/AES-%d] tampered packet rejected by ICV check", mode, bits)

	one[0] = extra.array[0]
	local okR = ffi.C.mg_ipsec_decrypt_burst(inb, one, 1, prepOk)
	check(okR == 0 and prepOk[0] == 0, "[%s/AES-%d] replayed packet rejected by anti-replay window", mode, bits)

	bufs:freeAll()
	extra:freeAll()
	ffi.C.mg_ipsec_sa_destroy(out)
	ffi.C.mg_ipsec_sa_destroy(inb)
	ffi.C.mg_ipsec_sa_destroy(inb2)
end

function master(args)
	ipsec.init(64)
	local spi = 1
	for _, mode in ipairs{"tunnel", "transport"} do
		for _, bits in ipairs{128, 256} do
			runMode(mode, bits, args.size, spi)
			spi = spi + 1
		end
	end
	if failed == 0 then
		log:info("All IPsec self tests passed")
	else
		log:error("%d IPsec self tests failed", failed)
	end
end
