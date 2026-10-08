--- ESP (AES-GCM) generator and receiver/decoder on the same port: the transmit tasks of ipsec-gen.lua and the
--- receive tasks of ipsec-sink.lua in one process, for bidirectional tests between two nodes that both run this script.
--- Sending: one TX queue, one core and one outbound SA per TX core; SA i uses SPI spiBase + i and outer
--- addresses tunnelLocal + i -> tunnelRemote.
--- Receiving: inbound SAs for the SPIs spiBase + i with outer addresses tunnelRemote + i -> tunnelLocal; one
--- rte_flow rule per SA steers it to RX queue i mod rxCores (with --rss: RSS hash of the outer IPs instead).
--- Only the receive offloads are switched off (ipsec-sink.lua switches off all of them): the NIC has to compute
--- the outer IPv4 checksum of the frames sent.
--- Node A: ./build/MoonGen examples/ipsec/ipsec-transceiver.lua --dpdk-config=examples/ipsec/dpdk-conf.lua <dev> --tx-cores 4 --rx-cores 4
--- Node B: the same with --tunnel-local 192.168.1.1 --tunnel-remote 192.168.0.1
--- It also works against ipsec-gen.lua and ipsec-sink.lua with their default addresses on node A.
local mg     = require "moongen"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local ipsec  = require "ipsec-sw"
-- txSlave, txSetup and txSummary come from ipsec-gen.lua, rxSlave and rxSummary from ipsec-sink.lua;
-- configure and master of these two files are replaced by the ones below
require "ipsec-gen"
require "ipsec-sink"

function configure(parser)
	parser:description("Sends ESP/AES-GCM encrypted UDP traffic and receives, decrypts and verifies the traffic of its peer on the same port.")
	parser:argument("dev", "Device to transmit from and receive on."):convert(tonumber)
	parser:option("--tx-cores", "Number of TX cores (= TX queues = SAs sent)."):default(1):convert(tonumber)
	parser:option("--rx-cores", "Number of RX cores (= RX queues)."):default(1):convert(tonumber)
	parser:option("-n --sas", "Number of SAs the peer sends (= its --tx-cores), default: own --tx-cores."):convert(tonumber)
	parser:option("-s --size", "Inner packet size (Ethernet frame without CRC) before encryption."):default(60):convert(tonumber)
	parser:option("-b --bits", "AES key length (128 or 256), ignored if --key is given."):default(256):convert(tonumber)
	parser:option("-k --key", "AES-GCM key + 4 byte salt as hex (RFC 4106 layout), used for both directions.")
	parser:option("-m --mode", "tunnel or transport."):default("tunnel")
	parser:option("--spi-base", "SPI of the first SA, used for both directions."):default(1000):convert(tonumber)
	parser:option("--tunnel-local", "Own outer IP: source of the first SA sent (incremented per SA), destination of the SAs received."):default("192.168.0.1")
	parser:option("--tunnel-remote", "Outer IP of the peer: destination of the SAs sent, source of the first SA received (incremented per SA)."):default("192.168.1.1")
	parser:option("--dst-mac", "Destination MAC of the encrypted frames."):default("ff:ff:ff:ff:ff:ff")
	parser:option("-r --rate", "Total send rate in Mpps, 0 = as fast as possible."):default(0):convert(tonumber)
	parser:option("--replay-window", "Anti-replay window size, 0 disables the check."):default(64):convert(tonumber)
	parser:option("--burst", "Burst size of the senders."):default(64):convert(tonumber)
	parser:option("--rx-burst", "Burst size of the receivers."):default(64):convert(tonumber)
	parser:option("--rx-descs", "Size of each RX ring."):default(4096):convert(tonumber)
	parser:flag("--rss", "Distribute the SAs received by RSS hash of the outer IPs instead of one rte_flow rule per SPI.")
	parser:option("-t --time", "Send time at the full rate in seconds, 0 = until Ctrl+C."):default(0):convert(tonumber)
	parser:option("--tx-delay", "Seconds to wait before sending, so that the receivers of the peer are ready."):default(2):convert(tonumber)
	parser:option("--ramp", "Seconds over which the send rate rises linearly to --rate at the start (not used without a rate limit)."):default(1):convert(tonumber)
	parser:option("--rx-linger", "Seconds to keep receiving after the own senders have stopped, to collect what the peer still sends."):default(2):convert(tonumber)
end

function master(args)
	if args.mode ~= "tunnel" and args.mode ~= "transport" then log:fatal("Mode must be tunnel or transport") end
	args.key = args.key or ipsec.testKey(args.bits)
	args.sas = args.sas or args.tx_cores
	local dev = device.config{port = args.dev, txQueues = args.tx_cores, rxQueues = args.rx_cores, rssQueues = args.rx_cores, rxDescs = args.rx_descs, disableRxOffloads = true}
	device.waitForLinks()
	ipsec.init(args.tx_cores + args.rx_cores * args.sas + 16)
	for i = 0, args.rss and -1 or args.sas - 1 do
		ipsec.steerSpi(dev:getRxQueue(i % args.rx_cores), args.spi_base + i)
	end
	-- the tasks expect the options under the names of ipsec-gen.lua and ipsec-sink.lua
	local tx, rx = {}, {}
	for k, v in pairs(args) do
		tx[k], rx[k] = v, v
	end
	tx.cores, tx.tunnel_src, tx.tunnel_dst = args.tx_cores, args.tunnel_local, args.tunnel_remote
	rx.cores, rx.tunnel_src, rx.tunnel_dst, rx.burst = args.rx_cores, args.tunnel_remote, args.tunnel_local, args.rx_burst
	-- the two nodes do not start at the same instant: the senders wait tx_delay before they start and the
	-- receivers run rx_linger longer than the senders, so that neither end of the run shows up as loss
	txSetup(tx)
	rx.txStart = tx.txStart
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
