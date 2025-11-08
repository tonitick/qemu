##### rover2
firmware_bin_path=../ws/rover2.bin
firmware_vtor_table_addr=0x08100000
tcp_port=1235
# ws_dir=/home/zhong/proj/bind/qemu/ws/ngc2_fusion_config/stage1
ws_dir=/home/zhong/proj/bind/Morpheus/output_function_semantics/0x08109bf0/collected_data/path_id_0_len_3/stage_2
./qemu-system-arm --plugin tests/tcg/plugins/libvirtual.so,virtual=${ws_dir}/virtuals.txt,modifier=${ws_dir}/modifier.txt,func_start_args=${ws_dir}/fstart_rand_setting.json,args=${ws_dir}/rand_setting.json,outs=${ws_dir}/out_setting.json,function_starts=${ws_dir}/function_start.txt,function_ends=${ws_dir}/function_ends.txt,sub_semantic_start=${ws_dir}/sub_semantic_start.txt,sub_semantic_end=${ws_dir}/sub_semantic_end.txt,dump_path=${ws_dir}/collected_data,sub_semantics_mode=1 \
    -d in_asm,op -D qemu.log -qmp unix:/tmp/qmp-sock,server,nowait \
    -machine cortexm,memory-backend=ram0 \
    -object memory-backend-file,id=ram0,mem-path=/dev/shm/my_m4_ram3_zz,size=512M,share=on -object memory-backend-file,id=ram1,mem-path=/dev/shm/my_m4_ram_zz,size=512K,share=on \
    -global cortexm-soc.shram_backend=ram1  -global cortexm-soc.ram_baseaddr=0x20000000  -global cortexm-soc.shram_baseaddr=0x30000000 \
    -cpu cortex-m7 -device loader,file=${firmware_bin_path},addr=0x08000000 -global armv7m.init-nsvtor=${firmware_vtor_table_addr} \
    -serial stdio -nographic -gdb tcp::${tcp_port} -S 2>&1 | tee log
