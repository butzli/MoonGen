--- Cleartext UDP receiver/checker, counterpart of plain-gen.lua and cleartext twin of ipsec-sink.lua.
--- One rte_flow rule per flow steers source IP src + i to RX queue i mod cores, like ipsec-sink.lua does
--- per SPI; with --rss the NIC distributes by RSS hash instead (uneven for few flows).
--- Reports per flow which queue(s) it arrived on and whether its sequence numbers are complete and in order.
--- ./build/MoonGen examples/ipsec/plain-sink.lua <rxDev> -c 4 -n 4 -t 25
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ipsec  = require "ipsec-sw" -- only for the flow rules

local MAGIC = 0x504c4149 -- "PLAI"

function configure(parser)
	parser:description("Receives and verifies the cleartext traffic from plain-gen.lua.")
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-c --cores", "Number of RX cores (= RX queues)."):default(1):convert(tonumber)
	parser:option("-n --flows", "Number of flows the sender uses (= its --cores)."):default(1):convert(tonumber)
	parser:option("--src", "Source IP of the first flow (incremented per flow)."):default("192.168.0.1")
	parser:flag("--rss", "Distribute the flows by RSS hash instead of one rte_flow rule per source IP.")
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("--rx-descs", "Size of each RX ring."):default(4096):convert(tonumber)
	parser:option("-t --time", "Run time in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
end

function master(args)
	local rxDev = device.config{port = args.rxDev, rxQueues = args.cores, rssQueues = args.cores, rxDescs = args.rx_descs, disableOffloads = true}
	device.waitForLinks()
	for i = 0, args.rss and -1 or args.flows - 1 do
		ipsec.steerSrcIp(rxDev:getRxQueue(i % args.cores), parseIP4Address(args.src) + i)
	end
	if args.time > 0 then mg.setRuntime(args.time) end
	local tasks = {}
	for i = 0, args.cores - 1 do
		tasks[i] = mg.startTask("rxSlave", rxDev:getRxQueue(i), args.burst)
	end
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	while mg.running() do
		ctr:update()
		mg.sleepMillisIdle(10)
	end
	ctr:finalize()
	-- merge the per-queue results: totals per flow and the queues it was seen on
	local flows, ids, other = {}, {}, 0
	for q = 0, args.cores - 1 do
		local res = tasks[q]:wait()
		other = other + res.other
		for id, f in pairs(res.flows) do
			if not flows[id] then
				flows[id], ids[#ids + 1] = {rx = 0, lost = 0, late = 0, queues = {}}, id
			end
			local e = flows[id]
			e.rx, e.lost, e.late = e.rx + f.rx, e.lost + f.lost, e.late + f.late
			e.queues[#e.queues + 1] = q
		end
	end
	table.sort(ids)
	local total = {rx = 0, lost = 0, late = 0, split = 0}
	for _, id in ipairs(ids) do
		local e = flows[id]
		log:info("Flow %d: received %d, missing %d, late/duplicate %d, queue(s) %s", id, e.rx, e.lost, e.late, table.concat(e.queues, ","))
		total.rx, total.lost, total.late = total.rx + e.rx, total.lost + e.lost, total.late + e.late
		if #e.queues > 1 then total.split = total.split + 1 end
	end
	log:info("Total: flows %d, received %d, missing %d, late/duplicate %d, flows on more than one queue %d, other packets %d",
		#ids, total.rx, total.lost, total.late, total.split, other)
	local nic = rxDev:getStats()
	log:info("NIC: delivered to the queues %d, dropped because a queue was full %d, errors %d, no buffers %d",
		tonumber(nic.ipackets), tonumber(nic.imissed), tonumber(nic.ierrors), tonumber(nic.rx_nombuf))
end

function rxSlave(queue, burst)
	local bufs = memory.bufArray(burst)
	local flows, other = {}, 0
	while mg.running() do
		local n = queue:tryRecv(bufs, 0)
		for i = 1, n do
			local payload = bufs[i]:getUdpPacket().payload
			if bufs[i]:getSize() >= 58 and payload.uint32[0] == MAGIC then
				local id, seq = payload.uint32[1], tonumber(payload.uint64[1])
				local f = flows[id]
				if not f then
					-- first packet of this flow on this queue: everything before it counts as missing
					f = {rx = 0, lost = seq, late = 0, exp = seq}
					flows[id] = f
				end
				f.rx = f.rx + 1
				if seq >= f.exp then
					f.lost = f.lost + (seq - f.exp)
					f.exp = seq + 1
				else
					-- sequence number from the past: reordered or duplicated; it was counted as missing before
					f.late = f.late + 1
				end
			else
				other = other + 1
			end
		end
		bufs:free(n)
	end
	return {flows = flows, other = other}
end
