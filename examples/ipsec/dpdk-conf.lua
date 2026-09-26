-- DPDK config for the IPsec examples: adds the ipsec_mb AES-GCM crypto device.
-- Usage: ./build/MoonGen --dpdk-config=examples/ipsec/dpdk-conf.lua examples/ipsec/ipsec-gen.lua ...
DPDKConfig {
	cli = {
		"--vdev=crypto_aesni_gcm0",
	},
}
