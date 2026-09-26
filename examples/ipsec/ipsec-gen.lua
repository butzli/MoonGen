--- ESP (AES-GCM) traffic generator, counterpart of ipsec-sink.lua.
--- One TX queue, one core and one outbound SA per core; SA i uses SPI spiBase + i
--- and outer source IP tunnelSrc + i, so the receiver's RSS spreads the SAs over its queues.
--- ./build/MoonGen --dpdk-config=examples/ipsec/dpdk-conf.lua examples/ipsec/ipsec-gen.lua <txDev> -c 4 -s 60
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ffi    = require "ffi"
local ipsec  = require "ipsec-sw"

local INNER_SRC_IP = "10.0.0.1" -- + core
local INNER_DST_IP = "10.1.0.1"
local SRC_PORT     = 1234
local DST_PORT     = 5678

function configure(parser)
	parser:description("Generates ESP/AES-GCM encrypted UDP traffic (rte_ipsec + CPU crypto), one SA per core.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:option("-c --cores", "Number of TX cores (= queues = SAs)."):default(1):convert(tonumber)
	parser:option("-s --size", "Inner packet size (Ethernet frame without CRC) before encryption."):default(60):convert(tonumber)
	parser:option("-b --bits", "AES key length (128 or 256), ignored if --key is given."):default(256):convert(tonumber)
	parser:option("-k --key", "AES-GCM key + 4 byte salt as hex (RFC 4106 layout).")
	parser:option("-m --mode", "tunnel or transport."):default("tunnel")
	parser:option("--spi-base", "SPI of the first SA."):default(1000):convert(tonumber)
	parser:option("--tunnel-src", "Outer source IP of the first SA (incremented per SA)."):default("192.168.0.1")
	parser:option("--tunnel-dst", "Outer destination IP."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC of the encrypted frames."):default("ff:ff:ff:ff:ff:ff")
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("-t --time", "Run time in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
end

-- inner packet template as Lua string (tasks cannot share cdata)
local function buildTemplate(dev, args, core)
	local mem = memory.createMemPool()
	local bufs = mem:bufArray(1)
	bufs:alloc(args.size)
	local pkt = bufs[1]:getUdpPacket()
	pkt:fill{
		ethSrc = dev,
		ethDst = args.dst_mac,
		ip4Src = parseIP4Address(INNER_SRC_IP) + core,
		ip4Dst = INNER_DST_IP,
		udpSrc = SRC_PORT,
		udpDst = DST_PORT,
		pktLength = args.size,
	}
	pkt.ip4:calculateChecksum()
	pkt.udp:setChecksum(0)
	local tmpl = ffi.string(bufs[1]:getData(), args.size)
	bufs:freeAll()
	return tmpl
end

function master(args)
	if args.mode ~= "tunnel" and args.mode ~= "transport" then
		log:fatal("Mode must be tunnel or transport")
	end
	args.key = args.key or ipsec.testKey(args.bits)
	local txDev = device.config{port = args.txDev, rxQueues = 1, txQueues = args.cores}
	device.waitForLinks()
	ipsec.init(args.cores + 16)
	if args.time > 0 then
		mg.setRuntime(args.time)
	end
	local tasks = {}
	for i = 0, args.cores - 1 do
		tasks[#tasks + 1] = mg.startTask("txSlave", txDev:getTxQueue(i), i, args, buildTemplate(txDev, args, i), txDev:getMacString())
	end
	local ctr = stats:newDevTxCounter(txDev, "plain")
	while mg.running() do
		ctr:update()
		mg.sleepMillisIdle(10)
	end
	ctr:finalize()
	local fails = 0
	for _, t in ipairs(tasks) do
		fails = fails + (t:wait() or 0)
	end
	log:info("Encryption failures: %d", fails)
end

function txSlave(queue, core, args, tmplStr, srcMac)
	local sa = ipsec.createSa{
		dir = "out",
		mode = args.mode,
		spi = args.spi_base + core,
		key = args.key,
		src = parseIP4Address(args.tunnel_src) + core,
		dst = args.tunnel_dst,
		srcMac = srcMac,
		dstMac = args.dst_mac,
		socket = select(2, mg.getCore()),
	}
	local tmplLen = #tmplStr
	local tmpl = ffi.new("uint8_t[?]", tmplLen)
	ffi.copy(tmpl, tmplStr, tmplLen)
	local mem = memory.createMemPool{n = 8191}
	local bufs = mem:bufArray(args.burst)
	local fails = ffi.new("uint64_t[1]")
	local first = true
	while mg.running() do
		bufs:alloc(tmplLen)
		local n = ipsec.encrypt(sa, bufs, bufs.size, tmpl, tmplLen, fails)
		if n > 0 then
			if first then
				first = false
				log:info("Core %d: SPI %d, inner frame %d B -> ESP frame %d B", core, args.spi_base + core, tmplLen, bufs.array[0].pkt_len)
			end
			queue:sendN(bufs, n)
		end
	end
	return tonumber(fails[0])
end
