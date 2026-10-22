--- Cleartext UDP receiver/checker, counterpart of plain-gen.lua and cleartext twin of ipsec-sink.lua.
--- One rte_flow rule per flow steers source IP src + i to RX queue i mod cores, like ipsec-sink.lua does
--- per SPI; with --rss the NIC distributes by RSS hash instead (uneven for few flows).
--- Reports per flow which queue(s) it arrived on and whether its sequence numbers are complete and in order.
--- Checks the generator payload of ipsec-sw.lua, so it also checks the traffic of ipsec-gen.lua after a device in
--- between has decrypted it (then --src is the inner source address of the first SA, 10.0.0.1 by default).
--- Packets without that payload are counted per queue as other packets. The receive tasks are also used by
--- plain-transceiver.lua.
--- ./build/MoonGen examples/ipsec/plain-sink.lua <rxDev> -c 4 -n 4 -t 25
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ipsec  = require "ipsec-sw" -- flow rules and payload check

function configure(parser)
	parser:description("Receives and verifies the cleartext traffic from plain-gen.lua.")
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-c --cores", "Number of RX cores (= RX queues)."):default(1):convert(tonumber)
	parser:option("-n --flows", "Number of flows the sender uses (= its --cores)."):default(1):convert(tonumber)
	parser:option("--src", "Source IP of the first flow (incremented per flow)."):default("192.168.0.1")
	parser:flag("--rss", "Distribute the flows by RSS hash instead of one rte_flow rule per source IP.")
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("--rx-descs", "Size of each RX ring."):default(4096):convert(tonumber)
	parser:flag("--offloads", "Keep libmoon's default receive offloads (checksum verification, VLAN, timestamps) instead of switching them off.")
	parser:option("-t --time", "Run time in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
end

function master(args)
	-- only the flows steered below are received, the rest stays with the kernel (ARP); RSS needs all frames
	if not args.rss then ipsec.isolate(args.rxDev) end
	local rxDev = device.config{port = args.rxDev, rxQueues = args.cores, rssQueues = args.cores, rxDescs = args.rx_descs, disableOffloads = not args.offloads}
	device.waitForLinks()
	for i = 0, args.rss and -1 or args.flows - 1 do
		ipsec.steerSrcIp(rxDev:getRxQueue(i % args.cores), parseIP4Address(args.src) + i)
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

--- Waits for the receive tasks and prints their results (also used by plain-transceiver.lua).
function rxSummary(tasks, args, rxDev)
	local flows = {}
	for q = 0, args.cores - 1 do
		local res, gap, gapAt = tasks[q]:wait()
		flows[q] = res
		log:info("Queue %d: longest pause between two receive calls %.3f ms at %.2f s", q, gap * 1e3, gapAt)
		-- with one flow rule per source address and no more flows than queues, this is the count of one flow
		log:info("Queue %d: other packets %d", q, res.other)
	end
	ipsec.flowSummary(flows, args.cores, "")
	local nic = rxDev:getStats()
	log:info("NIC: delivered to the queues %d, dropped because a queue was full %d, errors %d, no buffers %d",
		tonumber(nic.ipackets), tonumber(nic.imissed), tonumber(nic.ierrors), tonumber(nic.rx_nombuf))
end

function rxSlave(queue, core, args)
	local bufs = memory.bufArray(args.burst)
	local flows = ipsec.newFlows()
	-- plain-transceiver.lua keeps receiving for rx_linger seconds after its own senders have stopped
	local linger = (args.rx_linger or 0) * 1000
	-- diagnosis: longest time between two receive calls, i.e. the longest stall of this task; the time given is
	-- in seconds after the start of the senders (plain-transceiver.lua) or after the first second of this task
	local last = mg.getTime()
	local ref, maxGap, maxGapAt = args.txStart or last + 1, 0, 0
	while mg.running(linger) do
		ipsec.plainRx(queue, bufs, flows)
		local now = mg.getTime()
		if now - last > maxGap and now > ref then maxGap, maxGapAt = now - last, now - ref end
		last = now
	end
	return ipsec.flowResults(flows), maxGap, maxGapAt
end
