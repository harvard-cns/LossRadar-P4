LossRadar p4 code
========

## need to first modify the bmv2 simple_switch.cpp

A working modification to simple_switch.cpp is show in simple_switch_target/simple_switch.cpp.
All modifications are within:

	#if LOSSRADAR_ENABLE
	#endif

## How to run the example?

1. Feed the p4 code (p4src/lossradar_switch.p4) to the [p4c_bm](https://github.com/p4lang/p4c-bm).
	
	p4c-bmv2 p4src/lossradar_switch.p4 --json lossradar_switch.json

2. Build the [simple_switch](https://github.com/p4lang/behavioral-model/tree/master/targets/simple_switch) target in bmv2, with the modification provided in simple_switch_target/simple_switch.cpp.

3. Create a mininet, with the topology described in topo.txt

4. Set up the table rules, described in commands.txt

## How it works?

Please refer to the CoNext' 16 paper.
