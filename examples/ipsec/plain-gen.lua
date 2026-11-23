--- Cleartext UDP traffic generator, counterpart of plain-sink.lua and cleartext twin of ipsec-gen.lua.
--- One TX queue, one core and one flow per core; flow i uses source IP src + i (like the outer source IP of SA i in
--- ipsec-gen.lua), so the receiver's RSS spreads the flows over its queues.
--- With --tx-flows n the n flows are dealt out to the cores in turn (flow i to core i mod cores), and every core sends
--- its flows in turn, one burst each (like --tx-sas of ipsec-gen.lua); with --vary dst, flow i goes from src to dst + i
--- instead, e.g. to the inner addresses of the peers of a device in between (address plan in pos-scripts/ike).
--- The UDP payload is the generator payload of ipsec-sw.lua (magic, flow, sequence number per flow), the same as the
--- inner payload of ipsec-gen.lua, so that ipsec-sink.lua can check this traffic after a device in between has
--- encrypted it.
--- The transmit tasks are also used by plain-transceiver.lua.
--- ./build/MoonGen examples/ipsec/plain-gen.lua <txDev> -c 4 -s 60 -t 10
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local ffi    = require "ffi"
local log    = require "log"
-- ipsec-sw.lua: flow isolation, generator payload and NIC pacing
local ipsec  = require "ipsec-sw"

--- Command line options.
function configure(parser)
	parser:description("Generates cleartext UDP traffic with per-flow sequence numbers, one flow per core.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:option("-c --cores", "Number of TX cores (= queues)."):default(1):convert(tonumber)
	parser:option("--tx-flows", "Number of flows, at least --cores, dealt out to the cores; default: --cores."):convert(tonumber)
	parser:option("--vary", "Address incremented per flow: src or dst."):default("src")
	parser:option("-s --size", "Packet size (Ethernet frame without CRC), at least 60, or imix (ipsec.IMIX)."):default("60")
	parser:option("--src", "Source IP of the first flow (incremented per flow)."):default("192.168.0.1")
	parser:option("--dst", "Destination IP."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC."):default("ff:ff:ff:ff:ff:ff")
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("-t --time", "Send time at the full rate in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
	parser:option("--ramp", "Seconds over which the send rate rises linearly to --rate at the start (not used without a rate limit)."):default(1):convert(tonumber)
	parser:option("--ramp-stagger", "Milliseconds by which each transmit core changes from the ramp to the fixed schedule later than the previous one, so that the cores do not all change at the same instant."):default(50):convert(tonumber)
	parser:option("--nic-pacing", "With a rate limit: let the NIC send every packet at its time in the schedule, handing it over this many microseconds ahead (ipsec.newPacer); 0 = off."):default(20):convert(tonumber)
	parser:option("--pacing-group", "With --nic-pacing: only every n-th packet carries a time, the ones in between follow it back to back."):default(1):convert(tonumber)
end

--- Configures the port, starts one transmit task per core, shows the TX rate of the port until the end of the run and
--- then prints the results of the tasks.
function master(args)
	-- the frame sizes of --size: one, or the pattern of imix
	args.sizes = ipsec.sizes(args.size)
	checkFlows(args, args.cores)
	-- nothing is received here: all incoming frames stay with the kernel (ARP)
	ipsec.isolate(args.txDev)
	-- send on timestamp only for --nic-pacing with a rate limit; the PTP clock of the port gives the pacer the time of
	-- the NIC
	local txDev = device.config{port = args.txDev, txQueues = args.cores, sendOnTimestamp = args.nic_pacing > 0 and args.rate > 0}
	args.ptp = ipsec.ptpClock(args.txDev)
	device.waitForLinks()
	-- with a rate limit the senders start slowly, so that the receiver does not meet the full rate with cold caches
	if args.rate <= 0 then args.ramp = 0 end
	-- --time counts at the full rate: the run also covers the ramp
	if args.time > 0 then mg.setRuntime(args.ramp + args.time) end
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

--- Checks --tx-flows and --vary for cores transmit cores (also used by plain-transceiver.lua).
function checkFlows(args, cores)
	-- without --tx-flows one flow per core
	args.tx_flows = args.tx_flows or cores
	if args.tx_flows < cores or args.tx_flows > ipsec.MAX_FLOWS then log:fatal("--tx-flows must be between the number of TX cores and %d (payload flows)", ipsec.MAX_FLOWS) end
	if args.vary ~= "src" and args.vary ~= "dst" then log:fatal("--vary must be src or dst") end
end

--- Waits for the transmit tasks and prints their results (also used by plain-transceiver.lua).
function txSummary(tasks, args)
	local total, totalRate = 0, 0
	-- per core: one line with its results
	for i = 0, args.cores - 1 do
		local sent, rate, lag, lagAt, phases = tasks[i]:wait()
		log:info("Core %d: sent %d, largest backlog %.3f ms at %.2f s, catch-up phases %d", i, sent, lag * 1e3, lagAt, phases)
		total, totalRate = total + sent, totalRate + rate
	end
	log:info("Total: sent %d, rate %.2f Mpps", total, totalRate)
end

--- Transmit task of one core: sends bursts of its flows in turn, on a fixed schedule with a rate limit, otherwise as
--- fast as possible. Returns the packets sent, the rate reached and the diagnosis of the schedule.
function txSlave(queue, core, args)
	-- the flows of this core: core, core + cores, ... below tx_flows
	local flows = {}
	for i = core, (args.tx_flows or args.cores) - 1, args.cores do
		flows[#flows + 1] = i
	end
	-- filler(flow): function that fills a buffer with the UDP packet of the flow (len bytes, payload of the flow);
	-- --vary decides whether the flow number is added to the source or to the destination address
	local function filler(flow)
		local src, dst = parseIP4Address(args.src), parseIP4Address(args.dst)
		if args.vary == "dst" then dst = dst + flow else src = src + flow end
		return function(buf, len)
			local pkt = buf:getUdpPacket()
			pkt:fill{
				ethSrc = queue,
				ethDst = args.dst_mac,
				ip4Src = src,
				ip4Dst = dst,
				udpSrc = 1234,
				udpDst = 5678,
				pktLength = len,
			}
			pkt.ip4:calculateChecksum()
			pkt.udp:setChecksum(0)
			ipsec.fillPayload(pkt, flow)
		end
	end
	-- one size and one flow: everything except the sequence number is constant and filled only once; a size mix
	-- (imix) or several flows: every packet is copied from the template of its flow and size, in the order of the
	-- pattern (ipsec.fillMix), and each burst belongs to the next flow of the core
	local mix, size = #args.sizes > 1, args.sizes[1]
	local multi = mix or #flows > 1
	-- the mempool fills its buffers once at creation, but only in the case of one size and one flow
	local mem = memory.createMemPool{n = 8191, func = not multi and function(buf) filler(flows[1])(buf, size) end or nil}
	local bufs = mem:bufArray(args.burst)
	-- per flow of the core: its templates, its position in the size pattern and its sequence number
	local tmpls, poss, seqps = {}, {}, {}
	if multi then
		for j, flow in ipairs(flows) do
			tmpls[j], poss[j], seqps[j] = ipsec.mixTemplates(args.sizes, bufs, filler(flow)), ffi.new("uint16_t[1]"), ffi.new("uint64_t[1]")
		end
	end
	-- cur = the flow of the next burst; the mbufs are allocated for the largest size; seq counts the packets of the
	-- core
	local cur = 1
	local allocSize = math.max(unpack(args.sizes))
	local seq = 0
	-- rate limit: the bursts follow a fixed schedule; a backlog of more than 10 ms is dropped instead of caught up
	local interval = args.rate > 0 and args.burst * args.cores / (args.rate * 1e6) or 0
	-- plain-transceiver.lua gives its senders a common start time (args.txStart)
	while mg.running() and mg.getTime() < (args.txStart or 0) do
		mg.sleepMillis(1)
	end
	local start = mg.getTime()
	-- the achieved rate is measured from the change to the fixed schedule on; all cores reach the full rate after the
	-- ramp, and with --ramp-stagger each core changes later by its index times the stagger
	local fullStart, fullSeq = args.ramp > 0 and start + args.ramp + core * (args.ramp_stagger or 0) * 1e-3 or start, 0
	local ramping = args.ramp > 0
	-- diagnosis of the send schedule: largest backlog, when it occurred (seconds after the start)
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
			if lag > maxLag then maxLag, maxLagAt = lag, now - start end
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
				ramping, fullStart, fullSeq = false, now, seq
				nextSend = math.max(nextSend, now - 0.01) + interval
			else
				-- ramp: the rate rises with the elapsed share of the ramp, from at least 1 % of the full rate
				nextSend = now + interval / math.max(math.min((now - start) / args.ramp, 1), 0.01)
			end
		else
			-- fixed schedule; at most 10 ms of backlog is caught up
			nextSend = math.max(nextSend, now - 0.01) + interval
		end
		bufs:alloc(allocSize)
		if multi then
			-- size mix or several flows: copy from the templates of the current flow, then on to the next flow
			ipsec.fillMix(bufs, bufs.size, tmpls[cur], poss[cur], seqps[cur])
			cur = cur % #flows + 1
			seq = seq + bufs.size
		else
			-- one size and one flow: the buffers are filled already, only the sequence number is new
			for _, buf in ipairs(bufs) do
				ipsec.setPayloadSeq(buf:getUdpPacket(), seq)
				seq = seq + 1
			end
		end
		-- --nic-pacing: send times spaced evenly from due up to the next burst
		if pacer then pacer:stamp(bufs, bufs.size, due, (nextSend - due) / bufs.size) end
		queue:send(bufs)
	end
	-- rate since the change to the fixed schedule; below 99 % of the share of this core the run counts as not reached
	-- (the pos-scripts count these warnings)
	local rate = (seq - fullSeq) / (mg.getTime() - fullStart) / 1e6
	if rate < 0.99 * args.rate / args.cores then
		log:warn("Core %d: reached only %.2f of %.2f Mpps", core, rate, args.rate / args.cores)
	end
	return seq, rate, maxLag, maxLagAt, phases
end
