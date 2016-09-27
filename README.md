LossRadar p4 code
========

## need to first modify the bmv2 simple_switch.cpp

A working modification to simple_switch.cpp is show in simple_switch_target/simple_switch.cpp.
All modifications are within:

	#if LOSSRADAR_ENABLE
	#endif

## How it works?

First fed the p4 code (p4src/lossradar_switch.p4) to the [p4c_bm](https://github.com/p4lang/p4c-bm).
	
	p4c-bmv2 p4src/lossradar_switch.p4 --json lossradar_switch.json
