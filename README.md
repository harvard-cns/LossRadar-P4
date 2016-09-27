LossRadar p4 code
========

## need to first modify the bmv2 simple_switch.cpp

A working modification to simple_switch.cpp is show in simple_switch_target/simple_switch.cpp.
All modifications are within:

	#if LOSSRADAR_ENABLE
	#endif

The modification includs adding customized hash functions (the simple switch does not expose enough hash functions), and exposing the timestamp when packet arrive at the ingress pipeline (this is exposed by intrinsic_metadata.ingress_global_timestamp, but when I use that, the switch just does not work, so I add my own metadata).

## How to run the example?

1. Feed the p4 code (p4src/lossradar_switch.p4) to the [p4c_bm](https://github.com/p4lang/p4c-bm).
	
	p4c-bmv2 p4src/lossradar_switch.p4 --json lossradar_switch.json

2. Build the [simple_switch](https://github.com/p4lang/behavioral-model/tree/master/targets/simple_switch) target in bmv2, with the modification provided in simple_switch_target/simple_switch.cpp.

3. Create a mininet, with the topology described in topo.txt

4. Set up the table rules, described in commands.txt

## How it works?

Please refer to the CoNext' 16 paper.
