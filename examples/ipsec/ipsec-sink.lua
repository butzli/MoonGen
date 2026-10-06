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
	parser:option("--replay-window", "Anti-replay window size, 0 disables the check."):default(64):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("--rx-descs", "Size of each RX ring."):default(4096):convert(tonumber)
	parser:flag("--rss", "Distribute the SAs by RSS hash of the outer IPs instead of one rte_flow rule per SPI.")
	parser:option("-t --time", "Run time in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
end

function master(args)
	args.key = args.key or ipsec.testKey(args.bits)
	local rxDev = device.config{port = args.rxDev, rxQueues = args.cores, rssQueues = args.cores, rxDescs = args.rx_descs, disableOffloads = true}
	device.waitForLinks()
	ipsec.init(args.cores * args.sas + 16)
	for i = 0, args.rss and -1 or args.sas - 1 do
		ipsec.steerSpi(rxDev:getRxQueue(i % args.cores), args.spi_base + i)
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
	local total = {0, 0, 0, 0, 0, 0, 0}
	for i = 0, args.cores - 1 do
		for k, v in ipairs(tasks[i]:wait()) do
			total[k] = total[k] + v
		end
	end
	log:info("Total: " .. SUMMARY .. ", missing in between %d", unpack(total))
	local nic = rxDev:getStats()
	log:info("NIC: delivered to the queues %d, dropped because a queue was full %d, errors %d, no buffers %d",
		tonumber(nic.ipackets), tonumber(nic.imissed), tonumber(nic.ierrors), tonumber(nic.rx_nombuf))
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
			src = parseIP4Address(args.tunnel_src) + i,
			dst = args.tunnel_dst,
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
