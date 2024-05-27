do
	local args = { ... }
	local pcap_file = args[1]
	assert(pcap_file, "You should pass -X lua_script1:$PATH_TO_SOURCE_PCAP_FILE")
	local streams_table = {}
	local tcp_stream_f = Field.new("tcp.stream")
	-- local tcp_ack_f = Field.new("tcp.flags.ack")
	-- local tcp_fin_f = Field.new("tcp.flags.fin")
	-- local tcp_rst_f = Field.new("tcp.flags.reset")
	-- local tcp_syn_f = Field.new("tcp.flags.syn")
	local src_addr_f = Field.new("ip.src")
	-- local src_port_f = Field.new("tcp.srcport")
	local dst_addr_f = Field.new("ip.dst")
	-- local dst_port_f = Field.new("tcp.dstport")
	local tcp_num_flags = Field.new("tcp.flags")
	local frame_len = Field.new("frame.len")
	local frame_len_table = {}
	local flags_num_table = {}
	local src_ip_table = {}
	--local flag_time_table = {}
	local index = 0

	local function init_listener()
		local SYN = 2
		local tap = Listener.new("frame", "tcp")
		--local tap = Listener.new(nil, "tcp")
		--os.execute("mkdir -p streams")

		function tap.reset()
			--for _, value in pairs(streams_table) do
				--value.dumper:flush()
				--value.dumper:close()
			--end
		end

		function tap.packet(pinfo)
			local tcp_stream = tonumber(tostring(tcp_stream_f()))
			-- local fin = tonumber(tostring(tcp_fin_f()))
			-- local rst = tonumber(tostring(tcp_rst_f()))
			-- local ack = tonumber(tostring(tcp_ack_f()))
			-- local syn = tonumber(tostring(tcp_syn_f()))
			local src_addr = assert(tostring(src_addr_f()))
			-- local src_port = assert(tostring(src_port_f()))
			local dst_addr = assert(tostring(dst_addr_f()))
			-- local dst_port = assert(tostring(dst_port_f()))
			local num_flags = tonumber(tostring(tcp_num_flags()))
			local len = tonumber(tostring(frame_len()))
			-- local dump_info
			-- local part_pcap
			-- local index = tcp_stream
			-- if streams_table[index] == nil then
			-- 	flags_num_table[index] = {}
			-- 	part_pcap = string.format(
			-- 		"streams/%s-%s-%s-%s-%s-%d.pcap",
			-- 		pcap_file,
			-- 		src_addr,
			-- 		src_port,
			-- 		dst_addr,
			-- 		dst_port,
			-- 		index
			-- 	)
			-- 	streams_table[index] = {
			-- 		--dumper = nil,
			-- 		corrupted = not (syn == 1),
			-- 		finished = false,
			-- 		client = src_addr,
			-- 	}
				
			-- 	 flag_time_table[index] = {}
			-- 	 first_captured = pinfo.abs_ts
			-- 	 first_captured_rel = pinfo.rel_ts
			-- 	if streams_table[index].corrupted then
			-- 		streams_table[index].finished = true
			-- 	else
			-- 		streams_table[index].dumper = Dumper.new_for_current(part_pcap)
			-- 	end
			-- end
			flags_num_table[index] = {}
			src_ip_table[index] = {}
			frame_len_table[index] = {}
			-- if streams_table[index].finished then
			-- 	return
			-- end
			--streams_table[index].dumper:dump_current()
			table.insert(flags_num_table[index], num_flags)
			table.insert(frame_len_table[index],len)
			table.insert(src_ip_table[index],src_addr)
			-- table.insert(flag_time_table[index], pinfo.abs_ts)

			-- if src_addr == streams_table[index].client then
			-- 	if (fin == 1 and ack == 1) or rst == 1 then
			-- 		streams_table[index].finished = true

					-- dump_info =
						-- string.format("%s,%s,%s,%s,%s,%d", pcap_file, src_addr, src_port, dst_addr, dst_port, index)
					print(
						string.format(
							"%s,%s,%s,%s",
							-- dump_info,
							-- string.format("%.10f", -(first_captured - pinfo.abs_ts)),
							-- string.format("%.10f", -(first_captured_rel - pinfo.rel_ts)),
							-- string.format("%.10f", first_captured),
							-- string.format("%.10f", first_captured_rel),
							string.format("%s",pcap_file),
							table.concat(flags_num_table[index], ","),
							table.concat(frame_len_table[index],","),
							table.concat(src_ip_table[index],",")
						)
					)
					-- print(string.format("%s", table.concat(flag_time_table[index], ",")))
					-- print(pcap_file)
					-- print(string.format("%s",table.concat(flags_num_table[index],",")))
					-- print(string.format("%s",table.concat(frame_len_table[index],",")))
					-- print(string.format("%s",table.concat(src_ip_table[index],",")))
					--streams_table[index].dumper:flush()
					--streams_table[index].dumper:close()
					-- streams_table[index].finished = true
					-- index = index + 1
					return
			-- 	end
			-- end
		end
	end

	init_listener()
end
