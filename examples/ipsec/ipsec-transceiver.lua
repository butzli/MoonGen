--- ESP (AES-GCM) generator and receiver/decoder on the same port: ipsec-gen.lua and ipsec-sink.lua in one process,
--- for bidirectional tests between two nodes that both run this script.
--- Sending: one TX queue, one core and one outbound SA per TX core; SA i uses SPI spiBase + i and outer
--- addresses tunnelLocal + i -> tunnelRemote.
--- Receiving: inbound SAs for the SPIs spiBase + i with outer addresses tunnelRemote + i -> tunnelLocal; one
--- rte_flow rule per SA steers it to RX queue i mod rxCores (with --rss: RSS hash of the outer IPs instead).
--- Only the receive offloads are switched off (ipsec-sink.lua switches off all of them): the NIC has to compute
--- the outer IPv4 checksum of the frames sent.
--- Node A: ./build/MoonGen examples/ipsec/ipsec-transceiver.lua --dpdk-config=examples/ipsec/dpdk-conf.lua <dev> --tx-cores 4 --rx-cores 4
--- Node B: the same with --tunnel-local 192.168.1.1 --tunnel-remote 192.168.0.1
--- It also works against ipsec-gen.lua and ipsec-sink.lua with their default addresses on node A.
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ffi    = require "ffi"
local ipsec  = require "ipsec-sw"

local SUMMARY = "received %d, decrypted+authenticated %d, auth/ICV failures %d, replay/malformed drops %d, unknown SPI %d, non-ESP %d"
local FIELDS  = {"rx_pkts", "ok_pkts", "auth_fails", "prepare_drops", "unknown_spi", "non_esp"}

function configure(parser)
	parser:description("Sends ESP/AES-GCM encrypted UDP traffic and receives, decrypts and verifies the traffic of its peer on the same port.")
	parser:argument("dev", "Device to transmit from and receive on."):convert(tonumber)
	parser:option("--tx-cores", "Number of TX cores (= TX queues = SAs sent)."):default(1):convert(tonumber)
	parser:option("--rx-cores", "Number of RX cores (= RX queues)."):default(1):convert(tonumber)
	parser:option("-n --sas", "Number of SAs the peer sends (= its --tx-cores), default: own --tx-cores."):convert(tonumber)
	parser:option("-s --size", "Inner packet size (Ethernet frame without CRC) before encryption."):default(60):convert(tonumber)
	parser:option("-b --bits", "AES key length (128 or 256), ignored if --key is given."):default(256):convert(tonumber)
	parser:option("-k --key", "AES-GCM key + 4 byte salt as hex (RFC 4106 layout), used for both directions.")
	parser:option("-m --mode", "tunnel or transport."):default("tunnel")
	parser:option("--spi-base", "SPI of the first SA, used for both directions."):default(1000):convert(tonumber)
	parser:option("--tunnel-local", "Own outer IP: source of the first SA sent (incremented per SA), destination of the SAs received."):default("192.168.0.1")
	parser:option("--tunnel-remote", "Outer IP of the peer: destination of the SAs sent, source of the first SA received (incremented per SA)."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC of the encrypted frames."):default("ff:ff:ff:ff:ff:ff")
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--replay-window", "Anti-replay window size, 0 disables the check."):default(64):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("--rx-descs", "Size of each RX ring."):default(4096):convert(tonumber)
	parser:flag("--rss", "Distribute the SAs received by RSS hash of the outer IPs instead of one rte_flow rule per SPI.")
	parser:option("-t --time", "Run time in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
end

function master(args)
	if args.mode ~= "tunnel" and args.mode ~= "transport" then log:fatal("Mode must be tunnel or transport") end
	args.key = args.key or ipsec.testKey(args.bits)
	args.sas = args.sas or args.tx_cores
	local dev = device.config{port = args.dev, txQueues = args.tx_cores, rxQueues = args.rx_cores, rssQueues = args.rx_cores, rxDescs = args.rx_descs, disableRxOffloads = true}
	device.waitForLinks()
	ipsec.init(args.tx_cores + args.rx_cores * args.sas + 16)
	for i = 0, args.rss and -1 or args.sas - 1 do
		ipsec.steerSpi(dev:getRxQueue(i % args.rx_cores), args.spi_base + i)
	end
	if args.time > 0 then mg.setRuntime(args.time) end
	-- receivers first, so that they are ready when the peer and the own senders start
	local rxTasks, txTasks = {}, {}
	for i = 0, args.rx_cores - 1 do
		rxTasks[i] = mg.startTask("rxSlave", dev:getRxQueue(i), i, args)
	end
	for i = 0, args.tx_cores - 1 do
		txTasks[i] = mg.startTask("txSlave", dev:getTxQueue(i), i, args)
	end
	local txCtr = stats:newDevTxCounter(dev, "plain")
	local rxCtr = stats:newDevRxCounter(dev, "plain")
	while mg.running() do
		txCtr:update()
		rxCtr:update()
		mg.sleepMillisIdle(10)
	end
	txCtr:finalize()
	rxCtr:finalize()
	local fails, sent, rate = 0, 0, 0
	for i = 0, args.tx_cores - 1 do
		local f, s, r = txTasks[i]:wait()
		log:info("Core %d: SPI %d, packets sent %d", i, args.spi_base + i, s)
		fails, sent, rate = fails + f, sent + s, rate + r
	end
	log:info("Encryption failures: %d, packets sent: %d, rate %.2f Mpps", fails, sent, rate)
	local total = {0, 0, 0, 0, 0, 0, 0}
	for i = 0, args.rx_cores - 1 do
		for k, v in ipairs(rxTasks[i]:wait()) do
			total[k] = total[k] + v
		end
	end
	log:info("Total: " .. SUMMARY .. ", missing in between %d", unpack(total))
	local nic = dev:getStats()
	log:info("NIC: delivered to the queues %d, dropped because a queue was full %d, errors %d, no buffers %d",
		tonumber(nic.ipackets), tonumber(nic.imissed), tonumber(nic.ierrors), tonumber(nic.rx_nombuf))
end

function txSlave(queue, core, args)
	local sa = ipsec.createSa{
		dir = "out",
		mode = args.mode,
		spi = args.spi_base + core,
		key = args.key,
		src = parseIP4Address(args.tunnel_local) + core,
		dst = args.tunnel_remote,
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
	local interval = args.rate > 0 and args.burst * args.tx_cores / (args.rate * 1e6) or 0
	local start, sent = mg.getTime(), 0
	local nextSend = start
	while mg.running() do
		while mg.getTime() < nextSend do end
		nextSend = math.max(nextSend, mg.getTime() - 0.01) + interval
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
	local rate = sent / (mg.getTime() - start) / 1e6
	if rate < 0.99 * args.rate / args.tx_cores then
		log:warn("Core %d: reached only %.2f of %.2f Mpps", core, rate, args.rate / args.tx_cores)
	end
	return tonumber(fails[0]), sent, rate
end

function rxSlave(queue, core, args)
	-- own inbound SA instances for all SPIs; only those arriving on this queue are ever used
	local sas = {}
	for i = 0, args.sas - 1 do
		sas[i + 1] = ipsec.createSa{
			dir = "in",
			mode = args.mode,
			spi = args.spi_base + i,
			key = args.key,
			src = parseIP4Address(args.tunnel_remote) + i,
			dst = args.tunnel_local,
			replayWindow = args.replay_window,
			socket = select(2, mg.getCore()),
		}
	end
	local saTable = ipsec.createSaTable(sas)
	local st = ipsec.newRxStats()
	local bufs = memory.bufArray(args.burst)
	-- no output inside this loop: printing statistics here stalls it long enough for the RX queue to overflow
	while mg.running() do
		ipsec.rxDecrypt(queue, bufs, saTable, #sas, args.spi_base, st)
	end
	local res = {}
	for i, k in ipairs(FIELDS) do
		res[i] = tonumber(st[k])
	end
	log:info("Queue %d: " .. SUMMARY, core, unpack(res))
	-- per SA: packets missing between the first and the last sequence number received (the sender starts at 1)
	local missing = 0
	for i, sa in ipairs(sas) do
		local seen, first, last = ipsec.rxRange(sa)
		if seen > 0 then
			log:info("Queue %d: SPI %d: ESP sequence numbers %d..%d, received %d, missing in between %d",
				core, args.spi_base + i - 1, first, last, seen, last - first + 1 - seen)
			missing = missing + last - first + 1 - seen
		end
	end
	res[#FIELDS + 1] = missing
	return res
end
