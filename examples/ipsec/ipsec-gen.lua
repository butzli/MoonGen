--- ESP (AES-GCM) traffic generator, counterpart of ipsec-sink.lua.
--- One TX queue, one core and one outbound SA per core; SA i uses SPI spiBase + i and outer source IP tunnelSrc + i,
--- so the receiver's RSS spreads the SAs over its queues.
--- With --tx-sas n the n SAs are dealt out to the cores in turn (SA i to core i mod cores), and every core uses its
--- SAs in turn, one burst each. With --sa-file the SAs of the file are dealt out in the same way.
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

--- Command line options.
function configure(parser)
	parser:description("Generates ESP/AES-GCM encrypted UDP traffic (rte_ipsec + CPU crypto), one SA per core.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:option("-c --cores", "Number of TX cores (= queues), default 1; with --sa-file default: one per SA of the file."):convert(tonumber)
	parser:option("--tx-sas", "Number of outbound SAs, at least --cores, dealt out to the cores; default: --cores."):convert(tonumber)
	parser:option("-s --size", "Inner packet size (Ethernet frame without CRC) before encryption, at least 60, or imix (ipsec.IMIX)."):default("60")
	parser:option("-b --bits", "AES key length (128 or 256), ignored if --key is given."):default(256):convert(tonumber)
	parser:option("-k --key", "AES-GCM key + 4 byte salt as hex (RFC 4106 layout).")
	parser:option("-m --mode", "tunnel or transport."):default("tunnel")
	parser:option("--spi-base", "SPI of the first SA."):default(1000):convert(tonumber)
	parser:option("--tunnel-src", "Outer source IP of the first SA (incremented per SA)."):default("192.168.0.1")
	parser:option("--tunnel-dst", "Outer destination IP."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC of the encrypted frames."):default("ff:ff:ff:ff:ff:ff")
	parser:option("--sa-file", "SAs set up elsewhere (e.g. by IKE), see ipsec.loadSaFile; replaces --tx-sas, --key, --spi-base and the addresses.")
	parser:flag("--esn", "Extended (64 bit) sequence numbers; with --sa-file each SA says so itself.")
	parser:option("--seq-file", "Continue the ESP sequence numbers of an earlier run on the same SAs: read the next number per SPI from this file at the start (missing file or SPI: from 1) and write them back at the end, see ipsec.loadSeqFile; for a peer that keeps the SAs across runs.")
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("-t --time", "Send time at the full rate in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
	parser:option("--tx-delay", "Seconds to wait before sending."):default(0):convert(tonumber)
	parser:option("--ramp", "Seconds over which the send rate rises linearly to --rate at the start (not used without a rate limit)."):default(1):convert(tonumber)
	parser:option("--ramp-stagger", "Milliseconds by which each transmit core changes from the ramp to the fixed schedule later than the previous one, so that the cores do not all change at the same instant."):default(50):convert(tonumber)
	parser:option("--nic-pacing", "With a rate limit: let the NIC send every packet at its time in the schedule, handing it over this many microseconds ahead (ipsec.newPacer); 0 = off."):default(20):convert(tonumber)
	parser:option("--pacing-group", "With --nic-pacing: only every n-th packet carries a time, the ones in between follow it back to back."):default(4):convert(tonumber)
end

--- Configures the port and the crypto device, starts one transmit task per core, shows the TX rate of the port until
--- the end of the run and then prints the results of the tasks.
function master(args)
	if args.mode ~= "tunnel" and args.mode ~= "transport" then log:fatal("Mode must be tunnel or transport") end
	args.key = args.key or ipsec.testKey(args.bits)
	-- --sa-file: the outbound SAs of the file, their number replaces --tx-sas
	if args.sa_file then
		args.saList = ipsec.loadSaFile(args.sa_file, "out")
		if args.tx_sas and args.tx_sas ~= #args.saList then log:fatal("--tx-sas does not go with --sa-file") end
		args.tx_sas = #args.saList
	end
	-- default: one core per SA of the file, without a file one core
	args.cores = args.cores or (args.saList and #args.saList or 1)
	-- nothing is received here: all incoming frames stay with the kernel (ARP, IKE)
	ipsec.isolate(args.txDev)
	-- send on timestamp only for --nic-pacing with a rate limit; the PTP clock of the port gives the pacer the time of
	-- the NIC
	local txDev = device.config{port = args.txDev, txQueues = args.cores, sendOnTimestamp = args.nic_pacing > 0 and args.rate > 0}
	args.ptp = ipsec.ptpClock(args.txDev)
	device.waitForLinks()
	-- without --tx-sas one SA per core; the session pool of the crypto device holds all of them
	args.tx_sas = args.tx_sas or args.cores
	ipsec.init(args.tx_sas)
	txSetup(args)
	-- one transmit task per core, each on its own TX queue
	local tasks = {}
	for i = 0, args.cores - 1 do
		tasks[i] = mg.startTask("txSlave", txDev:getTxQueue(i), i, args)
	end
	-- TX rate of the port every 10 ms until the end of the run (--time or Ctrl+C)
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
	-- the frame sizes of --size: one, or the pattern of imix
	args.sizes = ipsec.sizes(args.size)
	if args.tx_sas < args.cores or args.tx_sas > ipsec.MAX_FLOWS then log:fatal("--tx-sas must be between --cores and %d (payload flows)", ipsec.MAX_FLOWS) end
	-- common start time of all transmit tasks
	args.txStart = mg.getTime() + args.tx_delay
	-- --seq-file: the sequence numbers of the earlier run, per SPI
	if args.seq_file then args.seqStart = ipsec.loadSeqFile(args.seq_file) end
	-- with a rate limit the senders start slowly, so that the receiver does not meet the full rate with cold
	-- caches and, in ipsec-transceiver.lua, while the transmit tasks of its own process are starting
	if args.rate <= 0 then args.ramp = 0 end
	-- --time counts at the full rate: the run also covers the delay and the ramp
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
	-- the core has the SAs core, core + cores, ... below tx_sas
	local n = math.floor((args.tx_sas - 1 - core) / args.cores) + 1
	if n == 1 then return "SPI " .. coreSa(args, core).spi end
	-- the SPIs of an SA file follow no pattern: only their number
	if args.saList then return ("%d SAs from the SA file"):format(n) end
	return ("%d SAs, SPIs %d..%d in steps of %d"):format(n, coreSa(args, core).spi, coreSa(args, core + (n - 1) * args.cores).spi, args.cores)
end

--- Waits for the transmit tasks and prints their results (also used by ipsec-transceiver.lua).
function txSummary(tasks, args)
	local fails, sent, rate, seqs = 0, 0, 0, {}
	-- per core: one line with its results; the next sequence numbers of its SAs are collected for --seq-file
	for i = 0, args.cores - 1 do
		local f, s, r, lag, lagAt, phases, nexts = tasks[i]:wait()
		seqs[#seqs + 1] = nexts
		log:info("Core %d: %s, packets sent %d, largest backlog %.3f ms at %.2f s, catch-up phases %d", i, coreSpis(args, i), s, lag * 1e3, lagAt, phases)
		fails, sent, rate = fails + f, sent + s, rate + r
	end
	log:info("Encryption failures: %d, packets sent: %d, rate %.2f Mpps", fails, sent, rate)
	if args.seq_file then ipsec.saveSeqFile(args.seq_file, table.concat(seqs)) end
end

--- Transmit task of one core: encrypts and sends bursts of its SAs in turn, on a fixed schedule with a rate limit,
--- otherwise as fast as possible. Returns the encryption failures, the packets sent, the rate reached, the diagnosis
--- of the schedule and the "out SPI NEXT" lines of its SAs.
function txSlave(queue, core, args)
	local mem = memory.createMemPool{n = 8191}
	local bufs = mem:bufArray(args.burst)
	-- per SA of the core: the SA, the inner packet template (encryption happens in place, so every mbuf is re-filled
	-- from it before each use) and the sequence number of its flow in the inner payload, written into every packet
	-- by ipsec.encrypt; with a size mix (imix) one template per size, used in the order of the pattern
	local mix, size = #args.sizes > 1, args.sizes[1]
	-- the mbufs are allocated for the largest size; pos = position in the size pattern
	local allocSize = math.max(unpack(args.sizes))
	local pos = ffi.new("uint16_t[1]")
	local nSas, sas, tmpls, seqs, spis = 0, {}, {}, {}, {}
	for i = core, args.tx_sas - 1, args.cores do
		nSas = nSas + 1
		local j = nSas
		local entry = coreSa(args, i)
		spis[j] = entry.spi
		sas[j] = ipsec.createSa{
			dir = "out",
			mode = args.mode,
			spi = entry.spi,
			key = entry.key,
			src = entry.src,
			dst = entry.dst,
			esn = entry.esn,
			seqStart = args.seqStart and args.seqStart.out[tostring(entry.spi)],
			srcMac = queue.dev:getMacString(),
			dstMac = args.dst_mac,
			socket = select(2, mg.getCore()),
		}
		-- inner UDP packet of SA i with len bytes and the payload of flow i; inner addresses from the SA file, without
		-- one 10.0.0.1 + i -> 10.1.0.1
		local function fill(buf, len)
			local pkt = buf:getUdpPacket()
			pkt:fill{
				ethSrc = queue,
				ethDst = args.dst_mac,
				ip4Src = entry.innerSrc or parseIP4Address("10.0.0.1") + i,
				ip4Dst = entry.innerDst or "10.1.0.1",
				udpSrc = 1234,
				udpDst = 5678,
				pktLength = len,
			}
			pkt.ip4:calculateChecksum()
			pkt.udp:setChecksum(0)
			ipsec.fillPayload(pkt, i)
		end
		tmpls[j] = mix and ipsec.mixTemplates(args.sizes, bufs, fill) or ipsec.template(bufs, size, fill)
		seqs[j] = ffi.new("uint64_t[1]")
	end
	-- the SA of the next burst (number cur) with its template and flow sequence number
	local cur, sa, tmpl, seq = 1, sas[1], tmpls[1], seqs[1]
	local fails = ffi.new("uint64_t[1]")
	-- the first burst sent logs the frame sizes
	local first = true
	-- rate limit: the bursts follow a fixed schedule; a backlog of more than 10 ms is dropped instead of caught up
	local interval = args.rate > 0 and args.burst * args.cores / (args.rate * 1e6) or 0
	-- wait for the common start time (--tx-delay)
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
	-- one burst per pass until the end of the run
	while mg.running() do
		-- busy wait until the burst is due; due = its time in the schedule
		while mg.getTime() < nextSend - lead do end
		local due = nextSend
		local now = mg.getTime() + lead
		-- with a rate limit: backlog behind the schedule for the diagnosis
		if interval > 0 then
			local lag = now - nextSend
			if lag > maxLag then maxLag, maxLagAt = lag, now - args.txStart end
			-- a new catch-up phase begins when the task falls more than 0.1 ms behind
			if lag > 0.0001 then
				if not behind then behind, phases = true, phases + 1 end
			else
				behind = false
			end
		end
		-- time of the next burst
		if ramping then
			if now >= fullStart then
				-- end of the ramp of this core: fixed schedule from here on, the achieved rate counts from now
				ramping, fullStart, fullSent = false, now, sent
				nextSend = math.max(nextSend, now - 0.01) + interval
			else
				-- ramp: the rate rises with the elapsed share of the ramp, from at least 1 % of the full rate
				nextSend = now + interval / math.max(math.min((now - start) / args.ramp, 1), 0.01)
			end
		else
			-- fixed schedule; at most 10 ms of backlog is caught up
			nextSend = math.max(nextSend, now - 0.01) + interval
		end
		-- several SAs: the next one in turn
		if nSas > 1 then
			cur = cur % nSas + 1
			sa, tmpl, seq = sas[cur], tmpls[cur], seqs[cur]
		end
		bufs:alloc(allocSize)
		-- fill and encrypt: a size mix is copied from its templates first, a single size is filled by ipsec.encrypt
		-- itself from the template, together with the sequence numbers
		local n
		if mix then
			ipsec.fillMix(bufs, bufs.size, tmpl, pos, seq)
			n = ipsec.encrypt(sa, bufs, bufs.size, nil, 0, fails, nil)
		else
			n = ipsec.encrypt(sa, bufs, bufs.size, tmpl, size, fails, seq)
		end
		-- send the n packets that were encrypted (ipsec.encrypt has freed the others)
		if n > 0 then
			if first then
				first = false
				log:info("Core %d: %s, inner frame %s B -> ESP frame %d B%s", core, coreSpis(args, core), args.size, bufs.array[0].pkt_len, mix and " (first one)" or "")
			end
			-- --nic-pacing: send times spaced evenly from due up to the next burst
			if pacer then pacer:stamp(bufs, n, due, (nextSend - due) / bufs.size) end
			queue:sendN(bufs, n)
			sent = sent + n
		end
	end
	-- rate since the change to the fixed schedule; below 99 % of the share of this core the run counts as not reached
	-- (the pos-scripts count these warnings)
	local rate = (sent - fullSent) / (mg.getTime() - fullStart) / 1e6
	if rate < 0.99 * args.rate / args.cores then
		log:warn("Core %d: reached only %.2f of %.2f Mpps", core, rate, args.rate / args.cores)
	end
	return tonumber(fails[0]), sent, rate, maxLag, maxLagAt, phases, ipsec.nextSeqs(sas, spis)
end
