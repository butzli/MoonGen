--- Cleartext UDP generator and receiver/checker on the same port: the transmit tasks of plain-gen.lua and the
--- receive tasks of plain-sink.lua in one process, the cleartext twin of ipsec-transceiver.lua. For bidirectional
--- cleartext tests between two nodes, and for the cleartext side of a device that en- and decrypts, whose ESP side
--- then runs ipsec-transceiver.lua.
--- Sending: one TX queue, one core and one flow per TX core; flow i goes from src + i to dst.
--- Receiving: one rte_flow rule per flow steers source address rxSrc + i to RX queue i mod rxCores (with --rss:
--- RSS hash instead). Both sides carry the same generator payload (ipsec-sw.lua), so the receivers also check the
--- traffic of ipsec-gen.lua after the device has decrypted it; packets without it are counted per queue as other.
--- Like ipsec-transceiver.lua, only the receive offloads are switched off.
--- Node A: ./build/MoonGen examples/ipsec/plain-transceiver.lua <dev> --tx-cores 4 --rx-cores 4
--- Node B: the same with --src 192.168.1.1 --dst 192.168.0.1 --rx-src 192.168.0.1
--- It also works against plain-gen.lua and plain-sink.lua with their default addresses on node A.
local mg     = require "moongen"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ipsec  = require "ipsec-sw" -- flow rules, isolated mode and generator payload
-- txSlave and txSummary come from plain-gen.lua, rxSlave and rxSummary from plain-sink.lua;
-- configure and master of these two files are replaced by the ones below
require "plain-gen"
require "plain-sink"

function configure(parser)
	parser:description("Sends cleartext UDP traffic with per-flow sequence numbers and receives and verifies the traffic of its peer on the same port.")
	parser:argument("dev", "Device to transmit from and receive on."):convert(tonumber)
	parser:option("--tx-cores", "Number of TX cores (= TX queues = flows sent)."):default(1):convert(tonumber)
	parser:option("--rx-cores", "Number of RX cores (= RX queues)."):default(1):convert(tonumber)
	parser:option("-n --flows", "Number of flows the peer sends (= its --tx-cores), default: own --tx-cores."):convert(tonumber)
	parser:option("-s --size", "Packet size (Ethernet frame without CRC), at least 60."):default(60):convert(tonumber)
	parser:option("--src", "Source IP of the first flow sent (incremented per flow)."):default("192.168.0.1")
	parser:option("--dst", "Destination IP of the flows sent."):default("192.168.1.1")
	parser:option("--rx-src", "Source IP of the first flow received (incremented per flow)."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC of the frames sent."):default("ff:ff:ff:ff:ff:ff")
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--burst", "Burst size of the senders."):default(64):convert(tonumber)
	parser:option("--rx-burst", "Burst size of the receivers."):default(64):convert(tonumber)
	parser:option("--rx-descs", "Size of each RX ring."):default(4096):convert(tonumber)
	parser:flag("--rss", "Distribute the flows received by RSS hash instead of one rte_flow rule per source IP.")
	parser:option("-t --time", "Send time at the full rate in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
	parser:option("--tx-delay", "Seconds to wait before sending, so that the receivers of the peer are ready."):default(2):convert(tonumber)
	parser:option("--ramp", "Seconds over which the send rate rises linearly to --rate at the start (not used without a rate limit)."):default(1):convert(tonumber)
	parser:option("--ramp-stagger", "Milliseconds by which each transmit core reaches the full rate later than the previous one at the end of the ramp, so that the cores do not all reach it at the same instant."):default(50):convert(tonumber)
	parser:option("--rx-linger", "Seconds to keep receiving after the own senders have stopped, to collect what the peer still sends."):default(2):convert(tonumber)
	parser:option("--nic-pacing", "With a rate limit: let the NIC send every packet at its time in the schedule, handing it over this many microseconds ahead (ipsec.newPacer); 0 = off."):default(20):convert(tonumber)
	parser:option("--pacing-group", "With --nic-pacing: only every n-th packet carries a time, the ones in between follow it back to back."):default(1):convert(tonumber)
end

function master(args)
	if args.size < ipsec.MIN_FRAME then log:fatal("Packet size must be at least %d (generator payload)", ipsec.MIN_FRAME) end
	args.flows = args.flows or args.tx_cores
	-- only the flows steered below are received, the rest stays with the kernel (ARP); RSS needs all frames
	if not args.rss then ipsec.isolate(args.dev) end
	local dev = device.config{port = args.dev, txQueues = args.tx_cores, rxQueues = args.rx_cores, rssQueues = args.rx_cores, rxDescs = args.rx_descs, disableRxOffloads = true, sendOnTimestamp = args.nic_pacing > 0 and args.rate > 0}
	args.ptp = ipsec.ptpClock(args.dev)
	device.waitForLinks()
	-- the tasks expect the options under the names of plain-gen.lua and plain-sink.lua
	local tx, rx = {}, {}
	for k, v in pairs(args) do
		tx[k], rx[k] = v, v
	end
	tx.cores = args.tx_cores
	rx.cores, rx.burst = args.rx_cores, args.rx_burst
	for i = 0, args.rss and -1 or args.flows - 1 do
		ipsec.steerSrcIp(dev:getRxQueue(i % args.rx_cores), parseIP4Address(args.rx_src) + i)
	end
	-- the two nodes do not start at the same instant: the senders wait tx_delay before they start and the
	-- receivers run rx_linger longer than the senders, so that neither end of the run shows up as loss
	-- (the same as txSetup in ipsec-gen.lua does for ipsec-transceiver.lua)
	if tx.rate <= 0 then tx.ramp = 0 end
	tx.txStart = mg.getTime() + args.tx_delay
	rx.txStart = tx.txStart
	if args.time > 0 then mg.setRuntime(args.tx_delay + tx.ramp + args.time) end
	-- receivers first, so that they are ready when the peer and the own senders start
	local rxTasks, txTasks = {}, {}
	for i = 0, args.rx_cores - 1 do
		rxTasks[i] = mg.startTask("rxSlave", dev:getRxQueue(i), i, rx)
	end
	for i = 0, args.tx_cores - 1 do
		txTasks[i] = mg.startTask("txSlave", dev:getTxQueue(i), i, tx)
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
	txSummary(txTasks, tx)
	rxSummary(rxTasks, rx, dev)
end
