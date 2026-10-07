--- Cleartext UDP traffic generator, counterpart of plain-sink.lua and cleartext twin of ipsec-gen.lua.
--- One TX queue, one core and one flow per core; flow i uses source IP src + i (like the outer source IP
--- of SA i in ipsec-gen.lua), so the receiver's RSS spreads the flows over its queues.
--- The UDP payload starts with a magic number (uint32), the flow id (uint32) and a sequence number (uint64).
--- ./build/MoonGen examples/ipsec/plain-gen.lua <txDev> -c 4 -s 60 -t 10
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"

local MAGIC = 0x504c4149 -- "PLAI"

function configure(parser)
	parser:description("Generates cleartext UDP traffic with per-flow sequence numbers, one flow per core.")
	parser:argument("txDev", "Device to transmit from."):convert(tonumber)
	parser:option("-c --cores", "Number of TX cores (= queues = flows)."):default(1):convert(tonumber)
	parser:option("-s --size", "Packet size (Ethernet frame without CRC), at least 58."):default(60):convert(tonumber)
	parser:option("--src", "Source IP of the first flow (incremented per flow)."):default("192.168.0.1")
	parser:option("--dst", "Destination IP."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC."):default("ff:ff:ff:ff:ff:ff")
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("-t --time", "Send time at the full rate in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
	parser:option("--ramp", "Seconds over which the send rate rises linearly to --rate at the start (not used without a rate limit)."):default(1):convert(tonumber)
end

function master(args)
	if args.size < 58 then log:fatal("Packet size must be at least 58") end
	local txDev = device.config{port = args.txDev, txQueues = args.cores}
	device.waitForLinks()
	-- with a rate limit the senders start slowly, so that the receiver does not meet the full rate with cold caches
	if args.rate <= 0 then args.ramp = 0 end
	if args.time > 0 then mg.setRuntime(args.ramp + args.time) end
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
	local total, totalRate = 0, 0
	for i = 0, args.cores - 1 do
		local sent, rate, lag, lagAt, phases = tasks[i]:wait()
		log:info("Flow %d: sent %d, largest backlog %.3f ms at %.2f s, catch-up phases %d", i, sent, lag * 1e3, lagAt, phases)
		total, totalRate = total + sent, totalRate + rate
	end
	log:info("Total: sent %d, rate %.2f Mpps", total, totalRate)
end

function txSlave(queue, flow, args)
	-- everything except the sequence number is constant per flow and filled only once
	local mem = memory.createMemPool{n = 8191, func = function(buf)
		local pkt = buf:getUdpPacket()
		pkt:fill{
			ethSrc = queue,
			ethDst = args.dst_mac,
			ip4Src = parseIP4Address(args.src) + flow,
			ip4Dst = args.dst,
			udpSrc = 1234,
			udpDst = 5678,
			pktLength = args.size,
		}
		pkt.ip4:calculateChecksum()
		pkt.udp:setChecksum(0)
		pkt.payload.uint32[0], pkt.payload.uint32[1] = MAGIC, flow
	end}
	local bufs = mem:bufArray(args.burst)
	local seq = 0
	-- rate limit: the bursts follow a fixed schedule; a backlog of more than 10 ms is dropped instead of caught up
	local interval = args.rate > 0 and args.burst * args.cores / (args.rate * 1e6) or 0
	local start = mg.getTime()
	-- the achieved rate is measured from the end of the ramp on
	local fullStart, fullSeq = args.ramp > 0 and start + args.ramp or start, 0
	local ramping = args.ramp > 0
	-- diagnosis of the send schedule: largest backlog, when it occurred (seconds after the start)
	-- and the number of phases in which the task was more than 0.1 ms behind and caught up at full speed
	local maxLag, maxLagAt, phases, behind = 0, 0, 0, false
	local nextSend = start
	while mg.running() do
		while mg.getTime() < nextSend do end
		local now = mg.getTime()
		if interval > 0 then
			local lag = now - nextSend
			if lag > maxLag then maxLag, maxLagAt = lag, now - start end
			if lag > 0.0001 then
				if not behind then behind, phases = true, phases + 1 end
			else
				behind = false
			end
		end
		if ramping then
			if now >= fullStart then
				ramping, fullStart, fullSeq = false, now, seq
				nextSend = math.max(nextSend, now - 0.01) + interval
			else
				nextSend = now + interval / math.max((now - start) / args.ramp, 0.01)
			end
		else
			nextSend = math.max(nextSend, now - 0.01) + interval
		end
		bufs:alloc(args.size)
		for _, buf in ipairs(bufs) do
			buf:getUdpPacket().payload.uint64[1] = seq
			seq = seq + 1
		end
		queue:send(bufs)
	end
	local rate = (seq - fullSeq) / (mg.getTime() - fullStart) / 1e6
	if rate < 0.99 * args.rate / args.cores then
		log:warn("Flow %d: reached only %.2f of %.2f Mpps", flow, rate, args.rate / args.cores)
	end
	return seq, rate, maxLag, maxLagAt, phases
end
