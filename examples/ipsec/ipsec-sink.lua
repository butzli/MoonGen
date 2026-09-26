--- ESP (AES-GCM) receiver/decoder, counterpart of ipsec-gen.lua.
--- RSS spreads the packets over the RX queues by outer IP; since each SA has its own outer source IP,
--- every SA is always handled by the same core, so the anti-replay state is never shared.
--- Every core decrypts, authenticates and counts the packets of its queue.
--- ./build/MoonGen --dpdk-config=examples/ipsec/dpdk-conf.lua examples/ipsec/ipsec-sink.lua <rxDev> -c 4 --sas 4
local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ipsec  = require "ipsec-sw"

function configure(parser)
	parser:description("Receives, decrypts and verifies ESP/AES-GCM traffic from ipsec-gen.lua.")
	parser:argument("rxDev", "Device to receive from."):convert(tonumber)
	parser:option("-c --cores", "Number of RX cores (= RSS queues)."):default(1):convert(tonumber)
	parser:option("-n --sas", "Number of SAs the sender uses (= its --cores)."):default(1):convert(tonumber)
	parser:option("-b --bits", "AES key length (128 or 256), ignored if --key is given."):default(256):convert(tonumber)
	parser:option("-k --key", "AES-GCM key + 4 byte salt as hex (RFC 4106 layout).")
	parser:option("-m --mode", "tunnel or transport."):default("tunnel")
	parser:option("--spi-base", "SPI of the first SA."):default(1000):convert(tonumber)
	parser:option("--tunnel-src", "Outer source IP of the first SA (incremented per SA)."):default("192.168.0.1")
	parser:option("--tunnel-dst", "Outer destination IP."):default("192.168.1.1")
	parser:option("--replay-window", "Anti-replay window size, 0 disables the check."):default(64):convert(tonumber)
	parser:option("--burst", "Burst size."):default(64):convert(tonumber)
	parser:option("-t --time", "Run time in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
end

function master(args)
	args.key = args.key or ipsec.testKey(args.bits)
	local rxDev = device.config{port = args.rxDev, rxQueues = args.cores, rssQueues = args.cores, txQueues = 1}
	device.waitForLinks()
	ipsec.init(args.cores * args.sas + 16)
	if args.time > 0 then
		mg.setRuntime(args.time)
	end
	local tasks = {}
	for i = 0, args.cores - 1 do
		tasks[#tasks + 1] = mg.startTask("rxSlave", rxDev:getRxQueue(i), i, args)
	end
	local ctr = stats:newDevRxCounter(rxDev, "plain")
	while mg.running() do
		ctr:update()
		mg.sleepMillisIdle(10)
	end
	ctr:finalize()
	local total = {}
	for _, t in ipairs(tasks) do
		for k, v in pairs(t:wait() or {}) do
			total[k] = (total[k] or 0) + v
		end
	end
	log:info("Total: received %d, decrypted+authenticated %d, auth/ICV failures %d, replay/malformed drops %d, unknown SPI %d, non-ESP %d",
		total.rx_pkts or 0, total.ok_pkts or 0, total.auth_fails or 0, total.prepare_drops or 0, total.unknown_spi or 0, total.non_esp or 0)
end

function rxSlave(queue, core, args)
	local socket = select(2, mg.getCore())
	-- own inbound SA instances for all SPIs; only those hashed to this queue are ever used
	local sas = {}
	for i = 0, args.sas - 1 do
		sas[#sas + 1] = ipsec.createSa{
			dir = "in",
			mode = args.mode,
			spi = args.spi_base + i,
			key = args.key,
			src = parseIP4Address(args.tunnel_src) + i,
			dst = args.tunnel_dst,
			replayWindow = args.replay_window,
			socket = socket,
		}
	end
	local saTable = ipsec.createSaTable(sas)
	local st = ipsec.newRxStats()
	local bufs = memory.bufArray(args.burst)
	local ctr = stats:newManualRxCounter(("Queue %d decrypted"):format(core), "plain")
	local lastPkts, lastInner = 0ULL, 0ULL
	while mg.running() do
		if ipsec.rxDecrypt(queue, bufs, saTable, #sas, args.spi_base, st) > 0 then
			-- throughput of the decrypted inner IP packets (without L2 header/CRC)
			local pkts, inner = st.ok_pkts - lastPkts, st.inner_bytes - lastInner
			lastPkts, lastInner = st.ok_pkts, st.inner_bytes
			ctr:update(tonumber(pkts), tonumber(inner))
		end
	end
	ctr:finalize()
	local res = {}
	for _, k in ipairs{"rx_pkts", "rx_bytes", "ok_pkts", "inner_bytes", "non_esp", "unknown_spi", "prepare_drops", "auth_fails"} do
		res[k] = tonumber(st[k])
	end
	log:info("Queue %d: received %d, decrypted %d, auth failures %d, replay/malformed drops %d, unknown SPI %d, non-ESP %d",
		core, res.rx_pkts, res.ok_pkts, res.auth_fails, res.prepare_drops, res.unknown_spi, res.non_esp)
	return res
end
