--- ESP (AES-GCM) traffic generator, counterpart of ipsec-sink.lua.
--- One TX queue, one core and one outbound SA per core; SA i uses SPI spiBase + i
--- and outer source IP tunnelSrc + i, so the receiver's RSS spreads the SAs over its queues.
--- ./build/MoonGen examples/ipsec/ipsec-gen.lua --dpdk-config=examples/ipsec/dpdk-conf.lua <txDev> -c 4 -s 60
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ffi    = require "ffi"
local ipsec  = require "ipsec-sw"

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
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("-t --time", "Send time at the full rate in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
	parser:option("--tx-delay", "Seconds to wait before sending."):default(0):convert(tonumber)
	parser:option("--ramp", "Seconds over which the send rate rises linearly to --rate at the start (not used without a rate limit)."):default(1):convert(tonumber)
end

function master(args)
	if args.mode ~= "tunnel" and args.mode ~= "transport" then log:fatal("Mode must be tunnel or transport") end
	args.key = args.key or ipsec.testKey(args.bits)
	local txDev = device.config{port = args.txDev, txQueues = args.cores}
	device.waitForLinks()
	ipsec.init(args.cores + 16)
	txSetup(args)
	local tasks = {}
	for i = 0, args.cores - 1 do
		tasks[i] = mg.startTask("txSlave", txDev:getTxQueue(i), i, args)
	end
	local ctr = stats:newDevTxCounter(txDev, "plain")
	while mg.running() do
		ctr:update()
		mg.sleepMillisIdle(10)
	end
	ctr:finalize()
	txSummary(tasks, args)
end

--- Fixes the start of the senders and the run time; to be called once before the transmit tasks are started
--- (also used by ipsec-transceiver.lua).
function txSetup(args)
	args.txStart = mg.getTime() + args.tx_delay
	-- with a rate limit the senders start slowly, so that the receiver does not meet the full rate with cold
	-- caches and, in ipsec-transceiver.lua, while the transmit tasks of its own process are starting
	if args.rate <= 0 then args.ramp = 0 end
	if args.time > 0 then mg.setRuntime(args.tx_delay + args.ramp + args.time) end
end

--- Waits for the transmit tasks and prints their results (also used by ipsec-transceiver.lua).
function txSummary(tasks, args)
	local fails, sent, rate = 0, 0, 0
	for i = 0, args.cores - 1 do
		local f, s, r, lag, lagAt, phases = tasks[i]:wait()
		log:info("Core %d: SPI %d, packets sent %d, largest backlog %.3f ms at %.2f s, catch-up phases %d", i, args.spi_base + i, s, lag * 1e3, lagAt, phases)
		fails, sent, rate = fails + f, sent + s, rate + r
	end
	log:info("Encryption failures: %d, packets sent: %d, rate %.2f Mpps", fails, sent, rate)
end

function txSlave(queue, core, args)
	local sa = ipsec.createSa{
		dir = "out",
		mode = args.mode,
		spi = args.spi_base + core,
		key = args.key,
		src = parseIP4Address(args.tunnel_src) + core,
		dst = args.tunnel_dst,
		srcMac = queue.dev:getMacString(),
		dstMac = args.dst_mac,
		socket = select(2, mg.getCore()),
	}
	local mem = memory.createMemPool{n = 8191}
	local bufs = mem:bufArray(args.burst)
	-- inner packet template: encryption happens in place, so every mbuf is re-filled from it before each use
	bufs:alloc(args.size)
	local pkt = bufs[1]:getUdpPacket()
	pkt:fill{
		ethSrc = queue,
		ethDst = args.dst_mac,
		ip4Src = parseIP4Address("10.0.0.1") + core,
		ip4Dst = "10.1.0.1",
		udpSrc = 1234,
		udpDst = 5678,
		pktLength = args.size,
	}
	pkt.ip4:calculateChecksum()
	pkt.udp:setChecksum(0)
	local tmpl = ffi.new("uint8_t[?]", args.size)
	ffi.copy(tmpl, bufs[1]:getData(), args.size)
	bufs:freeAll()
	local fails = ffi.new("uint64_t[1]")
	local first = true
	-- rate limit: the bursts follow a fixed schedule; a backlog of more than 10 ms is dropped instead of caught up
	local interval = args.rate > 0 and args.burst * args.cores / (args.rate * 1e6) or 0
	while mg.running() and mg.getTime() < args.txStart do
		mg.sleepMillis(1)
	end
	local start, sent = mg.getTime(), 0
	-- the achieved rate is measured from the end of the ramp on
	local fullStart, fullSent = args.ramp > 0 and start + args.ramp or start, 0
	local ramping = args.ramp > 0
	-- diagnosis of the send schedule: largest backlog, when it occurred (seconds after the senders started)
	-- and the number of phases in which the task was more than 0.1 ms behind and caught up at full speed
	local maxLag, maxLagAt, phases, behind = 0, 0, 0, false
	local nextSend = start
	while mg.running() do
		while mg.getTime() < nextSend do end
		local now = mg.getTime()
		if interval > 0 then
			local lag = now - nextSend
			if lag > maxLag then maxLag, maxLagAt = lag, now - args.txStart end
			if lag > 0.0001 then
				if not behind then behind, phases = true, phases + 1 end
			else
				behind = false
			end
		end
		if ramping then
			if now >= fullStart then
				ramping, fullStart, fullSent = false, now, sent
				nextSend = math.max(nextSend, now - 0.01) + interval
			else
				nextSend = now + interval / math.max((now - start) / args.ramp, 0.01)
			end
		else
			nextSend = math.max(nextSend, now - 0.01) + interval
		end
		bufs:alloc(args.size)
		local n = ipsec.encrypt(sa, bufs, bufs.size, tmpl, args.size, fails)
		if n > 0 then
			if first then
				first = false
				log:info("Core %d: SPI %d, inner frame %d B -> ESP frame %d B", core, args.spi_base + core, args.size, bufs.array[0].pkt_len)
			end
			queue:sendN(bufs, n)
			sent = sent + n
		end
	end
	local rate = (sent - fullSent) / (mg.getTime() - fullStart) / 1e6
	if rate < 0.99 * args.rate / args.cores then
		log:warn("Core %d: reached only %.2f of %.2f Mpps", core, rate, args.rate / args.cores)
	end
	return tonumber(fails[0]), sent, rate, maxLag, maxLagAt, phases
end
