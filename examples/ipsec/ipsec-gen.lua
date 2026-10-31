--- ESP (AES-GCM) traffic generator, counterpart of ipsec-sink.lua.
--- One TX queue, one core and one outbound SA per core; SA i uses SPI spiBase + i
--- and outer source IP tunnelSrc + i, so the receiver's RSS spreads the SAs over its queues.
--- With --tx-sas n the n SAs are dealt out to the cores in turn (SA i to core i mod cores), and every core uses its
--- SAs in turn, one burst each.
--- The inner UDP payload is the generator payload of ipsec-sw.lua (flow i = SA i, sequence number per flow), so
--- that plain-sink.lua can check the traffic after a device in between has decrypted it.
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
	parser:option("--tx-sas", "Number of outbound SAs, at least --cores, dealt out to the cores; default: --cores."):convert(tonumber)
	parser:option("-s --size", "Inner packet size (Ethernet frame without CRC) before encryption, at least 60."):default(60):convert(tonumber)
	parser:option("-b --bits", "AES key length (128 or 256), ignored if --key is given."):default(256):convert(tonumber)
	parser:option("-k --key", "AES-GCM key + 4 byte salt as hex (RFC 4106 layout).")
	parser:option("-m --mode", "tunnel or transport."):default("tunnel")
	parser:option("--spi-base", "SPI of the first SA."):default(1000):convert(tonumber)
	parser:option("--tunnel-src", "Outer source IP of the first SA (incremented per SA)."):default("192.168.0.1")
	parser:option("--tunnel-dst", "Outer destination IP."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC of the encrypted frames."):default("ff:ff:ff:ff:ff:ff")
	parser:option("--sa-file", "SAs set up elsewhere (e.g. by IKE), see ipsec.loadSaFile; replaces --cores, --key, --spi-base and the addresses.")
	parser:flag("--esn", "Extended (64 bit) sequence numbers; with --sa-file each SA says so itself.")
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("-t --time", "Send time at the full rate in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
	parser:option("--tx-delay", "Seconds to wait before sending."):default(0):convert(tonumber)
	parser:option("--ramp", "Seconds over which the send rate rises linearly to --rate at the start (not used without a rate limit)."):default(1):convert(tonumber)
	parser:option("--ramp-stagger", "Milliseconds by which each transmit core changes from the ramp to the fixed schedule later than the previous one, so that the cores do not all change at the same instant."):default(50):convert(tonumber)
	parser:option("--nic-pacing", "With a rate limit: let the NIC send every packet at its time in the schedule, handing it over this many microseconds ahead (ipsec.newPacer); 0 = off."):default(20):convert(tonumber)
	parser:option("--pacing-group", "With --nic-pacing: only every n-th packet carries a time, the ones in between follow it back to back."):default(4):convert(tonumber)
end

function master(args)
	if args.mode ~= "tunnel" and args.mode ~= "transport" then log:fatal("Mode must be tunnel or transport") end
	args.key = args.key or ipsec.testKey(args.bits)
	if args.sa_file then
		args.saList = ipsec.loadSaFile(args.sa_file, "out")
		args.cores = #args.saList
	end
	-- nothing is received here: all incoming frames stay with the kernel (ARP, IKE)
	ipsec.isolate(args.txDev)
	local txDev = device.config{port = args.txDev, txQueues = args.cores, sendOnTimestamp = args.nic_pacing > 0 and args.rate > 0}
	args.ptp = ipsec.ptpClock(args.txDev)
	device.waitForLinks()
	args.tx_sas = args.tx_sas or args.cores
	ipsec.init(args.tx_sas + 16)
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
	if args.size < ipsec.MIN_FRAME then log:fatal("Packet size must be at least %d (generator payload)", ipsec.MIN_FRAME) end
	if args.saList and args.tx_sas ~= args.cores then log:fatal("--tx-sas does not go with --sa-file") end
	if args.tx_sas < args.cores or args.tx_sas > ipsec.MAX_FLOWS then log:fatal("--tx-sas must be between --cores and %d (payload flows)", ipsec.MAX_FLOWS) end
	args.txStart = mg.getTime() + args.tx_delay
	-- with a rate limit the senders start slowly, so that the receiver does not meet the full rate with cold
	-- caches and, in ipsec-transceiver.lua, while the transmit tasks of its own process are starting
	if args.rate <= 0 then args.ramp = 0 end
	if args.time > 0 then mg.setRuntime(args.tx_delay + args.ramp + args.time) end
end

--- SA number i (that of core i mod cores): the entry of the SA file or, without one, the SA derived from the options.
local function coreSa(args, i)
	return args.saList and args.saList[i + 1] or {
		spi = args.spi_base + i,
		key = args.key,
		src = parseIP4Address(args.tunnel_src) + i,
		dst = args.tunnel_dst,
		esn = args.esn,
	}
end

--- SPI(s) of a core for the log.
local function coreSpis(args, core)
	local n = math.floor((args.tx_sas - 1 - core) / args.cores) + 1
	if n == 1 then return "SPI " .. coreSa(args, core).spi end
	return ("%d SAs, SPIs %d..%d in steps of %d"):format(n, coreSa(args, core).spi, coreSa(args, core + (n - 1) * args.cores).spi, args.cores)
end

--- Waits for the transmit tasks and prints their results (also used by ipsec-transceiver.lua).
function txSummary(tasks, args)
	local fails, sent, rate = 0, 0, 0
	for i = 0, args.cores - 1 do
		local f, s, r, lag, lagAt, phases = tasks[i]:wait()
		log:info("Core %d: %s, packets sent %d, largest backlog %.3f ms at %.2f s, catch-up phases %d", i, coreSpis(args, i), s, lag * 1e3, lagAt, phases)
		fails, sent, rate = fails + f, sent + s, rate + r
	end
	log:info("Encryption failures: %d, packets sent: %d, rate %.2f Mpps", fails, sent, rate)
end

function txSlave(queue, core, args)
	local mem = memory.createMemPool{n = 8191}
	local bufs = mem:bufArray(args.burst)
	-- per SA of the core: the SA, the inner packet template (encryption happens in place, so every mbuf is re-filled
	-- from it before each use) and the sequence number of its flow in the inner payload, written into every packet
	-- by ipsec.encrypt
	local nSas, sas, tmpls, seqs = 0, {}, {}, {}
	for i = core, args.tx_sas - 1, args.cores do
		nSas = nSas + 1
		local j = nSas
		local entry = coreSa(args, i)
		sas[j] = ipsec.createSa{
			dir = "out",
			mode = args.mode,
			spi = entry.spi,
			key = entry.key,
			src = entry.src,
			dst = entry.dst,
			esn = entry.esn,
			srcMac = queue.dev:getMacString(),
			dstMac = args.dst_mac,
			socket = select(2, mg.getCore()),
		}
		bufs:alloc(args.size)
		local pkt = bufs[1]:getUdpPacket()
		pkt:fill{
			ethSrc = queue,
			ethDst = args.dst_mac,
			ip4Src = entry.innerSrc or parseIP4Address("10.0.0.1") + i,
			ip4Dst = entry.innerDst or "10.1.0.1",
			udpSrc = 1234,
			udpDst = 5678,
			pktLength = args.size,
		}
		pkt.ip4:calculateChecksum()
		pkt.udp:setChecksum(0)
		ipsec.fillPayload(pkt, i)
		tmpls[j] = ffi.new("uint8_t[?]", args.size)
		ffi.copy(tmpls[j], bufs[1]:getData(), args.size)
		bufs:freeAll()
		seqs[j] = ffi.new("uint64_t[1]")
	end
	local cur, sa, tmpl, seq = 1, sas[1], tmpls[1], seqs[1]
	local fails = ffi.new("uint64_t[1]")
	local first = true
	-- rate limit: the bursts follow a fixed schedule; a backlog of more than 10 ms is dropped instead of caught up
	local interval = args.rate > 0 and args.burst * args.cores / (args.rate * 1e6) or 0
	while mg.running() and mg.getTime() < args.txStart do
		mg.sleepMillis(1)
	end
	local start, sent = mg.getTime(), 0
	-- the achieved rate is measured from the change to the fixed schedule on; all cores reach the full rate after the
	-- ramp, and with --ramp-stagger each core changes later by its index times the stagger
	local fullStart, fullSent = args.ramp > 0 and start + args.ramp + core * (args.ramp_stagger or 0) * 1e-3 or start, 0
	local ramping = args.ramp > 0
	-- diagnosis of the send schedule: largest backlog, when it occurred (seconds after the senders started)
	-- and the number of phases in which the task was more than 0.1 ms behind and caught up at full speed
	local maxLag, maxLagAt, phases, behind = 0, 0, 0, false
	-- --nic-pacing: each burst is handed to the NIC lead seconds ahead of its time, the NIC sends its packets spaced
	-- evenly up to the next burst; the schedule below is unchanged (it counts in send times, now = time + lead)
	local pacer = (args.nic_pacing or 0) > 0 and interval > 0 and ipsec.newPacer(args.ptp, args.nic_pacing * 1e-6, args.pacing_group)
	local lead = pacer and pacer.lead or 0
	local nextSend = start
	while mg.running() do
		while mg.getTime() < nextSend - lead do end
		local due = nextSend
		local now = mg.getTime() + lead
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
				nextSend = now + interval / math.max(math.min((now - start) / args.ramp, 1), 0.01)
			end
		else
			nextSend = math.max(nextSend, now - 0.01) + interval
		end
		if nSas > 1 then
			cur = cur % nSas + 1
			sa, tmpl, seq = sas[cur], tmpls[cur], seqs[cur]
		end
		bufs:alloc(args.size)
		local n = ipsec.encrypt(sa, bufs, bufs.size, tmpl, args.size, fails, seq)
		if n > 0 then
			if first then
				first = false
				log:info("Core %d: %s, inner frame %d B -> ESP frame %d B", core, coreSpis(args, core), args.size, bufs.array[0].pkt_len)
			end
			if pacer then pacer:stamp(bufs, n, due, (nextSend - due) / bufs.size) end
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
