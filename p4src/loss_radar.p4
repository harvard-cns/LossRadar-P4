#define N_PORT 4
#define N_PORT_IDX_WIDTH 2

#define LOSSRADAR_SIZE 32
#define LOSSRADAR_IDX_WIDTH 5

#define LOSSRADAR_SUB_SIZE 8
#define LOSSRADAR_SUB_IDX_WIDTH 3

// round_up(LOSSRADAR_SIZE * N_PORT) to 2^x, becasue in register_read(x, arr, idx), the length of arr has to be at least the max number index could be. For example, if idx is 7 bits, then len(arr) must be at least 128. (this is not shown in any spec, but only with this setting can work in the bm)
#define BATCH_SIZE 128
// LOSSRADAR_IDX_WIDTH + N_PORT_IDX_WIDTH
#define BATCH_WIDTH 7

#define TOTAL_SIZE 256
#define TOTAL_WIDTH 8

#define LOSSRADAR_TIMESTAMP_WIDTH 13
#define LOSSRADAR_TIMESTAMP_MAX 8192

// exposed by the bm
header_type lossradar_metadata_t{
	fields {
		ingress_timestamp : 48;
	}
}
metadata lossradar_metadata_t lossradar_metadata;

header_type lr_tmp_t{
	fields {
		original_ttl: 8;
		this_batch: 1;
		ingress_timestamp: LOSSRADAR_TIMESTAMP_WIDTH;

		um_h1: TOTAL_WIDTH;
		um_h2: TOTAL_WIDTH;
		um_h3: TOTAL_WIDTH;

		dm_h1: TOTAL_WIDTH;
		dm_h2: TOTAL_WIDTH;
		dm_h3: TOTAL_WIDTH;

		tmp_srcip: 32;
		tmp_dstip: 32;
		tmp_srcport: 16;
		tmp_dstport: 16;
		tmp_protocol: 8;
		tmp_ipid: 16;
		tmp_timestamp: LOSSRADAR_TIMESTAMP_WIDTH;
		tmp_ttl: 8;
		tmp_pkt_cnt: 16;
	}
}
metadata lr_tmp_t lr_tmp;

field_list um_packet{
	ipv4.srcAddr;
	ipv4.dstAddr;
	tcp.srcPort;
	tcp.dstPort;
	lossradar_hdr.protocol;
	ipv4.identification;
	lr_tmp.ingress_timestamp;
	ipv4.ttl;
}

field_list dm_packet{
	ipv4.srcAddr;
	ipv4.dstAddr;
	tcp.srcPort;
	tcp.dstPort;
	lossradar_hdr.protocol;
	ipv4.identification;
	lossradar_hdr.timestamp;
	lr_tmp.original_ttl;
}

field_list_calculation um_hash1{
	input{
		um_packet;
	}
	algorithm: my_hash1;
	output_width: LOSSRADAR_SUB_IDX_WIDTH;
}

field_list_calculation um_hash2{
	input{
		um_packet;
	}
	algorithm: my_hash2;
	output_width: LOSSRADAR_SUB_IDX_WIDTH;
}

field_list_calculation um_hash3{
	input{
		um_packet;
	}
	algorithm: my_hash3;
	output_width: LOSSRADAR_SUB_IDX_WIDTH;
}

field_list_calculation dm_hash1{
	input{
		dm_packet;
	}
	algorithm: my_hash1;
	output_width: LOSSRADAR_SUB_IDX_WIDTH;
}

field_list_calculation dm_hash2{
	input{
		dm_packet;
	}
	algorithm: my_hash2;
	output_width: LOSSRADAR_SUB_IDX_WIDTH;
}

field_list_calculation dm_hash3{
	input{
		dm_packet;
	}
	algorithm: my_hash3;
	output_width: LOSSRADAR_SUB_IDX_WIDTH;
}

// lossradar upstream meter
register um_pkt_cnt{
	width:16;
	instance_count: TOTAL_SIZE;
}
register um_xor_srcip{
	width:32;
	instance_count: TOTAL_SIZE;
}
register um_xor_dstip{
	width:32;
	instance_count: TOTAL_SIZE;
}
register um_xor_srcport{
	width:16;
	instance_count: TOTAL_SIZE;
}
register um_xor_dstport{
	width:16;
	instance_count: TOTAL_SIZE;
}
register um_xor_protocol{
	width:8;
	instance_count: TOTAL_SIZE;
}
register um_xor_ipid{
	width:16;
	instance_count: TOTAL_SIZE;
}
register um_xor_timestamp{
	width:LOSSRADAR_TIMESTAMP_WIDTH;
	instance_count: TOTAL_SIZE;
}
register um_xor_ttl{
	width:8;
	instance_count: TOTAL_SIZE;
}

// lossradar downstream meter
register dm_pkt_cnt{
	width:16;
	instance_count: TOTAL_SIZE;
}
register dm_xor_srcip{
	width:32;
	instance_count: TOTAL_SIZE;
}
register dm_xor_dstip{
	width:32;
	instance_count: TOTAL_SIZE;
}
register dm_xor_srcport{
	width:16;
	instance_count: TOTAL_SIZE;
}
register dm_xor_dstport{
	width:16;
	instance_count: TOTAL_SIZE;
}
register dm_xor_protocol{
	width:8;
	instance_count: TOTAL_SIZE;
}
register dm_xor_ipid{
	width:16;
	instance_count: TOTAL_SIZE;
}
register dm_xor_timestamp{
	width:LOSSRADAR_TIMESTAMP_WIDTH;
	instance_count: TOTAL_SIZE;
}
register dm_xor_ttl{
	width:8;
	instance_count: TOTAL_SIZE;
}
//debug 
register debug{
	width: 32;
	instance_count: 100;
}

action add_lossradar_hdr(){
	add_header(lossradar_hdr);
	modify_field(lossradar_hdr.protocol, ipv4.protocol);
	modify_field(ipv4.protocol, IPV4_LOSSRADAR);
	add_to_field(ipv4.totalLen, 3);
}
table add_loss_radar_hdr_table{
	reads {
		ipv4.protocol: exact;
	}
	actions {
		add_lossradar_hdr;
		_no_op;
	}
	size: 10;
}

action remove_lossradar_hdr(){
	modify_field(ipv4.protocol, lossradar_hdr.protocol);
	remove_header(lossradar_hdr);
	add_to_field(ipv4.totalLen, -3);
}
table remove_loss_radar_hdr_table{
	reads {
		standard_metadata.egress_port: exact;
		ipv4.protocol: exact;
	}
	actions {
		remove_lossradar_hdr;
		_no_op;
	}
	size: 2;
}

action loss_radar_calc_hash(){
	// update metadata
	modify_field(lr_tmp.original_ttl, ipv4.ttl + 1);
	modify_field(lr_tmp.this_batch, (lossradar_metadata.ingress_timestamp/LOSSRADAR_TIMESTAMP_MAX%2));
	modify_field(lr_tmp.ingress_timestamp, lossradar_metadata.ingress_timestamp%LOSSRADAR_TIMESTAMP_MAX);

	// update um
	// 1. calculate the index to the IBF
	modify_field_with_hash_based_offset(lr_tmp.um_h1, 0 + LOSSRADAR_SIZE * standard_metadata.egress_spec + BATCH_SIZE * lr_tmp.this_batch, um_hash1, LOSSRADAR_SUB_SIZE);
	modify_field_with_hash_based_offset(lr_tmp.um_h2, LOSSRADAR_SUB_SIZE + LOSSRADAR_SIZE * standard_metadata.egress_spec + BATCH_SIZE * lr_tmp.this_batch, um_hash2, LOSSRADAR_SUB_SIZE);
	modify_field_with_hash_based_offset(lr_tmp.um_h3, LOSSRADAR_SUB_SIZE * 2 + LOSSRADAR_SIZE * standard_metadata.egress_spec + BATCH_SIZE * lr_tmp.this_batch, um_hash3, LOSSRADAR_SUB_SIZE);

	// update dm
	modify_field_with_hash_based_offset(lr_tmp.dm_h1, 0 + LOSSRADAR_SIZE * standard_metadata.ingress_port + BATCH_SIZE * lossradar_hdr.batchID, dm_hash1, LOSSRADAR_SUB_SIZE);
	modify_field_with_hash_based_offset(lr_tmp.dm_h2, LOSSRADAR_SUB_SIZE + LOSSRADAR_SIZE * standard_metadata.ingress_port + BATCH_SIZE * lossradar_hdr.batchID, dm_hash2, LOSSRADAR_SUB_SIZE);
	modify_field_with_hash_based_offset(lr_tmp.dm_h3, LOSSRADAR_SUB_SIZE * 2 + LOSSRADAR_SIZE * standard_metadata.ingress_port + BATCH_SIZE * lossradar_hdr.batchID, dm_hash3, LOSSRADAR_SUB_SIZE);
}
table loss_radar_calc_hash_table{
	actions{
		loss_radar_calc_hash;
	}
}

action loss_radar_um(){
	// 2. change the register
	// count 
	register_read(lr_tmp.tmp_pkt_cnt, um_pkt_cnt, lr_tmp.um_h1);
	add_to_field(lr_tmp.tmp_pkt_cnt, 1);
	register_write(um_pkt_cnt, lr_tmp.um_h1, lr_tmp.tmp_pkt_cnt);

	register_read(lr_tmp.tmp_pkt_cnt, um_pkt_cnt, lr_tmp.um_h2);
	add_to_field(lr_tmp.tmp_pkt_cnt, 1);
	register_write(um_pkt_cnt, lr_tmp.um_h2, lr_tmp.tmp_pkt_cnt);

	register_read(lr_tmp.tmp_pkt_cnt, um_pkt_cnt, lr_tmp.um_h3);
	add_to_field(lr_tmp.tmp_pkt_cnt, 1);
	register_write(um_pkt_cnt, lr_tmp.um_h3, lr_tmp.tmp_pkt_cnt);

	// srcip
	register_read(lr_tmp.tmp_srcip, um_xor_srcip, lr_tmp.um_h1);
	modify_field(lr_tmp.tmp_srcip, lr_tmp.tmp_srcip ^ ipv4.srcAddr);
	register_write(um_xor_srcip, lr_tmp.um_h1, lr_tmp.tmp_srcip);

	register_read(lr_tmp.tmp_srcip, um_xor_srcip, lr_tmp.um_h2);
	modify_field(lr_tmp.tmp_srcip, lr_tmp.tmp_srcip ^ ipv4.srcAddr);
	register_write(um_xor_srcip, lr_tmp.um_h2, lr_tmp.tmp_srcip);

	register_read(lr_tmp.tmp_srcip, um_xor_srcip, lr_tmp.um_h3);
	modify_field(lr_tmp.tmp_srcip, lr_tmp.tmp_srcip ^ ipv4.srcAddr);
	register_write(um_xor_srcip, lr_tmp.um_h3, lr_tmp.tmp_srcip);

	// ipid
	register_read(lr_tmp.tmp_ipid, um_xor_ipid, lr_tmp.um_h1);
	modify_field(lr_tmp.tmp_ipid, lr_tmp.tmp_ipid ^ ipv4.identification);
	register_write(um_xor_ipid, lr_tmp.um_h1, lr_tmp.tmp_ipid);

	register_read(lr_tmp.tmp_ipid, um_xor_ipid, lr_tmp.um_h2);
	modify_field(lr_tmp.tmp_ipid, lr_tmp.tmp_ipid ^ ipv4.identification);
	register_write(um_xor_ipid, lr_tmp.um_h2, lr_tmp.tmp_ipid);

	register_read(lr_tmp.tmp_ipid, um_xor_ipid, lr_tmp.um_h3);
	modify_field(lr_tmp.tmp_ipid, lr_tmp.tmp_ipid ^ ipv4.identification);
	register_write(um_xor_ipid, lr_tmp.um_h3, lr_tmp.tmp_ipid);

	// timestamp
	register_read(lr_tmp.tmp_timestamp, um_xor_timestamp, lr_tmp.um_h1);
	modify_field(lr_tmp.tmp_timestamp, lr_tmp.tmp_timestamp ^ lossradar_metadata.ingress_timestamp);
	register_write(um_xor_timestamp, lr_tmp.um_h1, lr_tmp.tmp_timestamp);

	register_read(lr_tmp.tmp_timestamp, um_xor_timestamp, lr_tmp.um_h2);
	modify_field(lr_tmp.tmp_timestamp, lr_tmp.tmp_timestamp ^ lossradar_metadata.ingress_timestamp);
	register_write(um_xor_timestamp, lr_tmp.um_h2, lr_tmp.tmp_timestamp);

	register_read(lr_tmp.tmp_timestamp, um_xor_timestamp, lr_tmp.um_h3);
	modify_field(lr_tmp.tmp_timestamp, lr_tmp.tmp_timestamp ^ lossradar_metadata.ingress_timestamp);
	register_write(um_xor_timestamp, lr_tmp.um_h3, lr_tmp.tmp_timestamp);

	// ttl
	register_read(lr_tmp.tmp_ttl, um_xor_ttl, lr_tmp.um_h1);
	modify_field(lr_tmp.tmp_ttl, lr_tmp.tmp_ttl ^ ipv4.ttl);
	register_write(um_xor_ttl, lr_tmp.um_h1, lr_tmp.tmp_ttl);

	register_read(lr_tmp.tmp_ttl, um_xor_ttl, lr_tmp.um_h2);
	modify_field(lr_tmp.tmp_ttl, lr_tmp.tmp_ttl ^ ipv4.ttl);
	register_write(um_xor_ttl, lr_tmp.um_h2, lr_tmp.tmp_ttl);

	register_read(lr_tmp.tmp_ttl, um_xor_ttl, lr_tmp.um_h3);
	modify_field(lr_tmp.tmp_ttl, lr_tmp.tmp_ttl ^ ipv4.ttl);
	register_write(um_xor_ttl, lr_tmp.um_h3, lr_tmp.tmp_ttl);

}
table loss_radar_um_table{ // only update if the packet is not dropped, so that we ca exclude the expected drops.
	reads {
		ipv4: valid;
		ipv4.protocol: exact;
		drop_metadata.drop : exact;
	}
	actions{
		loss_radar_um;
		_no_op;
	}
	size: 10;
}

action loss_radar_dm(){
	// update dm
	// count 
	register_read(lr_tmp.tmp_pkt_cnt, dm_pkt_cnt, lr_tmp.dm_h1);
	add_to_field(lr_tmp.tmp_pkt_cnt, 1);
	register_write(dm_pkt_cnt, lr_tmp.dm_h1, lr_tmp.tmp_pkt_cnt);

	register_read(lr_tmp.tmp_pkt_cnt, dm_pkt_cnt, lr_tmp.dm_h2);
	add_to_field(lr_tmp.tmp_pkt_cnt, 1);
	register_write(dm_pkt_cnt, lr_tmp.dm_h2, lr_tmp.tmp_pkt_cnt);

	register_read(lr_tmp.tmp_pkt_cnt, dm_pkt_cnt, lr_tmp.dm_h3);
	add_to_field(lr_tmp.tmp_pkt_cnt, 1);
	register_write(dm_pkt_cnt, lr_tmp.dm_h3, lr_tmp.tmp_pkt_cnt);

	// srcip
	register_read(lr_tmp.tmp_srcip, dm_xor_srcip, lr_tmp.dm_h1);
	modify_field(lr_tmp.tmp_srcip, lr_tmp.tmp_srcip ^ ipv4.srcAddr);
	register_write(dm_xor_srcip, lr_tmp.dm_h1, lr_tmp.tmp_srcip);

	register_read(lr_tmp.tmp_srcip, dm_xor_srcip, lr_tmp.dm_h2);
	modify_field(lr_tmp.tmp_srcip, lr_tmp.tmp_srcip ^ ipv4.srcAddr);
	register_write(dm_xor_srcip, lr_tmp.dm_h2, lr_tmp.tmp_srcip);

	register_read(lr_tmp.tmp_srcip, dm_xor_srcip, lr_tmp.dm_h3);
	modify_field(lr_tmp.tmp_srcip, lr_tmp.tmp_srcip ^ ipv4.srcAddr);
	register_write(dm_xor_srcip, lr_tmp.dm_h3, lr_tmp.tmp_srcip);

	// ipid
	register_read(lr_tmp.tmp_ipid, dm_xor_ipid, lr_tmp.dm_h1);
	modify_field(lr_tmp.tmp_ipid, lr_tmp.tmp_ipid ^ ipv4.identification);
	register_write(dm_xor_ipid, lr_tmp.dm_h1, lr_tmp.tmp_ipid);

	register_read(lr_tmp.tmp_ipid, dm_xor_ipid, lr_tmp.dm_h2);
	modify_field(lr_tmp.tmp_ipid, lr_tmp.tmp_ipid ^ ipv4.identification);
	register_write(dm_xor_ipid, lr_tmp.dm_h2, lr_tmp.tmp_ipid);

	register_read(lr_tmp.tmp_ipid, dm_xor_ipid, lr_tmp.dm_h3);
	modify_field(lr_tmp.tmp_ipid, lr_tmp.tmp_ipid ^ ipv4.identification);
	register_write(dm_xor_ipid, lr_tmp.dm_h3, lr_tmp.tmp_ipid);

	// timestamp
	register_read(lr_tmp.tmp_timestamp, dm_xor_timestamp, lr_tmp.dm_h1);
	modify_field(lr_tmp.tmp_timestamp, lr_tmp.tmp_timestamp ^ lossradar_hdr.timestamp);
	register_write(dm_xor_timestamp, lr_tmp.dm_h1, lr_tmp.tmp_timestamp);

	register_read(lr_tmp.tmp_timestamp, dm_xor_timestamp, lr_tmp.dm_h2);
	modify_field(lr_tmp.tmp_timestamp, lr_tmp.tmp_timestamp ^ lossradar_hdr.timestamp);
	register_write(dm_xor_timestamp, lr_tmp.dm_h2, lr_tmp.tmp_timestamp);

	register_read(lr_tmp.tmp_timestamp, dm_xor_timestamp, lr_tmp.dm_h3);
	modify_field(lr_tmp.tmp_timestamp, lr_tmp.tmp_timestamp ^ lossradar_hdr.timestamp);
	register_write(dm_xor_timestamp, lr_tmp.dm_h3, lr_tmp.tmp_timestamp);

	// ttl
	register_read(lr_tmp.tmp_ttl, dm_xor_ttl, lr_tmp.dm_h1);
	modify_field(lr_tmp.tmp_ttl, lr_tmp.tmp_ttl ^ lr_tmp.original_ttl);
	register_write(dm_xor_ttl, lr_tmp.dm_h1, lr_tmp.tmp_ttl);

	register_read(lr_tmp.tmp_ttl, dm_xor_ttl, lr_tmp.dm_h2);
	modify_field(lr_tmp.tmp_ttl, lr_tmp.tmp_ttl ^ lr_tmp.original_ttl);
	register_write(dm_xor_ttl, lr_tmp.dm_h2, lr_tmp.tmp_ttl);

	register_read(lr_tmp.tmp_ttl, dm_xor_ttl, lr_tmp.dm_h3);
	modify_field(lr_tmp.tmp_ttl, lr_tmp.tmp_ttl ^ lr_tmp.original_ttl);
	register_write(dm_xor_ttl, lr_tmp.dm_h3, lr_tmp.tmp_ttl);

	// update batchID and timestamp
	modify_field(lossradar_hdr.batchID, (lossradar_metadata.ingress_timestamp/LOSSRADAR_TIMESTAMP_MAX%2));
	modify_field(lossradar_hdr.timestamp, lossradar_metadata.ingress_timestamp);
}
table loss_radar_dm_table{ // no matter dropped or not, update the dm, so that we can exclude the expected drops (dropped by tables)
	reads {
		ipv4: valid;
		ipv4.protocol: exact;
	}
	actions{
		loss_radar_dm;
		_no_op;
	}
	size: 10;
}
