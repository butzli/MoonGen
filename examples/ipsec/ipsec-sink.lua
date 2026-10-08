--- ESP (AES-GCM) receiver/decoder, counterpart of ipsec-gen.lua.
--- One rte_flow rule per SA steers SPI spiBase + i to RX queue i mod cores, so every SA is always handled
--- by the same core (the anti-replay state is never shared) and the SAs are spread evenly over the cores.
--- With --rss the NIC distributes by RSS hash of the outer IPs instead (uneven for few SAs).
--- Every core decrypts, authenticates and counts the packets of its queue.
--- ./build/MoonGen examples/ipsec/ipsec-sink.lua --dpdk-config=examples/ipsec/dpdk-conf.lua <rxDev> -c 4 --sas 4
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ipsec  = require "ipsec-sw"

local SUMMARY = "received %d, decrypted+authenticated %d, auth/ICV failures %d, replay/malformed drops %d, unknown SPI %d, non-ESP %d"
local FIELDS  = {"rx_pkts", "ok_pkts", "auth_fails", "prepare_drops", "unknown_spi", "non_esp"}

function configure(parser)
	parser:description("Receives, decrypts and verifies ESP/AES-GCM traffic from ipsec-gen.lua.")
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-c --cores", "Number of RX cores (= RX queues)."):default(1):convert(tonumber)
	parser:option("-n --sas", "Number of SAs the sender uses (= its --cores)."):default(1):convert(tonumber)
	parser:option("-b --bits", "AES key length (128 or 256), ignored if --key is given."):default(256):convert(tonumber)
	parser:option("-k --key", "AES-GCM key + 4 byte salt as hex (RFC 4106 layout).")
	parser:option("-m --mode", "tunnel or transport."):default("tunnel")
	parser:option("--spi-base", "SPI of the first SA."):default(1000):convert(tonumber)
	parser:option("--tunnel-src", "Outer source IP of the first SA (incremented per SA)."):default("192.168.0.1")
	parser:option("--tunnel-dst", "Outer destination IP."):default("192.168.1.1")
	parser:option("--sa-file", "SAs set up elsewhere (e.g. by IKE), see ipsec.loadSaFile; replaces --sas, --key, --spi-base and the addresses.")
	parser:flag("--esn", "Extended (64 bit) sequence numbers; with --sa-file each SA says so itself.")
	parser:option("--replay-window","Anti-replay window size, 0 disables the check."):default(64):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("--rx-descs", "Size of each RX ring."):default(4096):convert(tonumber)
	parser:flag("--offloads", "Keep libmoon's default receive offloads (checksum verification, VLAN, timestamps) instead of switching them off.")
	parser:flag("--rss", "Distribute the SAs by RSS hash of the outer IPs instead of one rte_flow rule per SPI.")
	parser:option("-t --time", "Run time in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
end

function master(args)
	args.key = args.key or ipsec.testKey(args.bits)
	if args.sa_file then
		args.saList = ipsec.loadSaFile(args.sa_file, "in")
		args.sas = #args.saList
	end
	-- only the SAs steered below are received, the rest stays with the kernel (ARP, IKE); RSS needs all frames
	if not args.rss then ipsec.isolate(args.rxDev) end
	local rxDev = device.config{port = args.rxDev, rxQueues = args.cores, rssQueues = args.cores, rxDescs = args.rx_descs, disableOffloads = not args.offloads}
	device.waitForLinks()
	ipsec.init(args.cores * args.sas + 16)
	for i = 0, args.rss and -1 or args.sas - 1 do
		ipsec.steerSpi(rxDev:getRxQueue(i % args.cores), rxSa(args, i).spi)
	end
	if args.time > 0 then mg.setRuntime(args.time) end
	local tasks = {}
	for i = 0, args.cores - 1 do
		tasks[i] = mg.startTask("rxSlave", rxDev:getRxQueue(i), i, args)
	end
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	while mg.running() do
		ctr:update()
		mg.sleepMillisIdle(10)
	end
	ctr:finalize()
	rxSummary(tasks, args, rxDev)
end

--- Waits for the receive tasks and prints their results (also used by ipsec-transceiver.lua).
function rxSummary(tasks, args, rxDev)
	local total = {0, 0, 0, 0, 0, 0, 0}
	for i = 0, args.cores - 1 do
		local res, gap, gapAt = tasks[i]:wait()
		for k, v in ipairs(res) do
			total[k] = total[k] + v
		end
		log:info("Queue %d: longest pause between two receive calls %.3f ms at %.2f s", i, gap * 1e3, gapAt)
	end
	log:info("Total: " .. SUMMARY .. ", missing in between %d", unpack(total))
	local nic = rxDev:getStats()
	log:info("NIC: delivered to the queues %d, dropped because a queue was full %d, errors %d, no buffers %d",
		tonumber(nic.ipackets), tonumber(nic.imissed), tonumber(nic.ierrors), tonumber(nic.rx_nombuf))
end

--- SA number i: the entry of the SA file or, without one, the SA derived from the options.
function rxSa(args, i)
	return args.saList and args.saList[i + 1] or {
		spi = args.spi_base + i,
		key = args.key,
		src = parseIP4Address(args.tunnel_src) + i,
		dst = args.tunnel_dst,
		esn = args.esn,
	}
end

function rxSlave(queue, core, args)
	-- own inbound SA instances for all SPIs; only those arriving on this queue are ever used
	local sas, spis = {}, {}
	for i = 0, args.sas - 1 do
		local entry = rxSa(args, i)
		sas[i + 1] = ipsec.createSa{
			dir = "in",
			mode = args.mode,
			spi = entry.spi,
			key = entry.key,
			src = entry.src,
			dst = entry.dst,
			esn = entry.esn,
			replayWindow = args.replay_window,
			socket = select(2, mg.getCore()),
		}
		spis[i + 1] = entry.spi
	end
	-- the SPIs of an SA file are arbitrary: hash table instead of the table indexed by SPI - spiBase
	local saTable, numSas, spiBase = ipsec.createSaTable(sas), #sas, args.spi_base
	if args.saList then
		saTable, numSas = ipsec.createSpiTable(sas, spis)
		spiBase = 0
	end
	local st = ipsec.newRxStats()
	local bufs = memory.bufArray(args.burst)
	-- no output inside this loop: printing statistics here stalls it long enough for the RX queue to overflow
	-- ipsec-transceiver.lua keeps receiving for rx_linger seconds after its own senders have stopped
	local linger = (args.rx_linger or 0) * 1000
	-- diagnosis: longest time between two receive calls, i.e. the longest stall of this task; the time given is
	-- in seconds after the start of the senders (ipsec-transceiver.lua) or after the first second of this task
	local last = mg.getTime()
	local ref, maxGap, maxGapAt = args.txStart or last + 1, 0, 0
	while mg.running(linger) do
		ipsec.rxDecrypt(queue, bufs, saTable, numSas, spiBase, st)
		local now = mg.getTime()
		if now - last > maxGap and now > ref then maxGap, maxGapAt = now - last, now - ref end
		last = now
	end
	local res = {}
	for i, k in ipairs(FIELDS) do
		res[i] = tonumber(st[k])
	end
	log:info("Queue %d: " .. SUMMARY, core, unpack(res))
	-- per SA: packets missing between the first and the last sequence number received (the sender starts at 1);
	-- these are the 32 bits carried in the packets, so the count holds across one wrap but not beyond 2^32 packets
	local missing = 0
	for i, sa in ipairs(sas) do
		local seen, first, last = ipsec.rxRange(sa)
		if seen > 0 then
			local gap = (last - first) % 2^32 + 1 - seen
			log:info("Queue %d: SPI %d: ESP sequence numbers %d..%d, received %d, missing in between %d",
				core, spis[i], first, last, seen, gap)
			missing = missing + gap
		end
	end
	res[#FIELDS + 1] = missing
	return res, maxGap, maxGapAt
end
