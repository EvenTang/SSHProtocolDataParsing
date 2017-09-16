# coding: utf-8

class Array
    def AddIndentToStrs(indent = "")
        self.map! { |item| indent + item }
    end
end

def PrintFormatBinData(data, count_one_line) 
    str_out_ary = []
    s_idx = 0
    e_idx = s_idx + count_one_line
    e_idx = data.size if e_idx > data.size;
    line_len = count_one_line
    line_len = data.size if count_one_line > data.size
    layout_num = line_len * 2 + (line_len - 1)
    while s_idx < data.size
        printable_str = data[s_idx...e_idx].map{|i| i.chr }.join().gsub(/[^[:print:]]/,'.')        
        str_out_ary.push ("%-#{layout_num}s     %s" % [data[s_idx...e_idx].map{|i| "%02X" % i }.join(" "), printable_str])
        s_idx = e_idx
        e_idx = s_idx + count_one_line;
        e_idx = data.size if e_idx > data.size;
    end
    str_out_ary.AddIndentToStrs("| ")
end

def PrintStrFieldAsString(field_name, data) 
    output_str_ary = []
    str = data.map{|i| i.chr }.join()
    output_str_ary.push "%s : [%s] " % [field_name, str]
    yield str if block_given?
    output_str_ary += PrintFormatBinData(data, 16).AddIndentToStrs(" " * (field_name.size + 1))
end

def PrintAllStr(str_ary)
    str_ary.each do |item|
        puts item
    end
end

def PrintNumFieldAsString(field_name, data) 
    output_str_ary = []
    num = data.map{|i| "%02X" % i }.join().to_i(16)
    output_str_ary.push "%s : [%s] " % [field_name, num.to_s]
    yield num if block_given?
    output_str_ary += PrintFormatBinData(data, 16).AddIndentToStrs(" " * (field_name.size + 1))
end

def PrintOctFieldAsString(field_name, data) 
    output_str_ary = []
    oct_str = data.map{|i| "%02X" % i }.join()
    output_str_ary.push "%s : [%s] " % [field_name, oct_str]
    yield oct_str if block_given?
    output_str_ary += PrintFormatBinData(data, 16).AddIndentToStrs(" " * (field_name.size + 1))
end

def PrintDataByDataStructDescription(data_form, data)
    print_by_types = {
        :NUM_FIELD => method(:PrintNumFieldAsString),
        :STR_FIELD => method(:PrintStrFieldAsString),
        :OCT_FIELD => method(:PrintOctFieldAsString)
    }

    output_str_ary = []    
    current = 0
    data_form.each do |field|
        if field[:filed_update] != nil then
            field[:field_size] = field[:filed_update].call() 
        end
        output_str_ary += print_by_types[field[:field_type]].call(
            field[:field_name], data[current...(current + field[:field_size])]) {|content| field[:field_content] = content} 
        current += field[:field_size]
    end
    output_str_ary
end

# direction | string | : "Server->Client" or "Client->Server"
def PrintSSHHello(data, direction)
    puts "PrintSSHHello"
    output_str_ary = [
        "=======================================================================",
        ">> PrintSSHHello   " + direction, 
        "-----------------------------------------------------------------------"]

    data_format = [
        {:field_name => "Protocol", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0,
         :filed_update => ->() { data.map{|i| "%02X" % i }.join().index("0D0A") / 2 + 2 } }
    ]
    output_str_ary += PrintDataByDataStructDescription(data_format, data)

    total_size = 0
    data_format.each do |item|
        total_size += item[:field_size]
    end
    yield total_size if block_given?
    output_str_ary[1] += " [Total : %d bytes ] " % total_size
    output_str_ary
end

def PrintKeyExchangeInit()
    data_format = [
        {:field_name => "Packet length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Padding length", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Message Code", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Cookie", :field_size => 16, :field_type => :OCT_FIELD, :field_content => 0},
        {:field_name => "Kex_algorithms length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Kex_algorithms string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Kex_algorithms length"}[:field_content] }},
        {:field_name => "server_host_key_algorithm length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "server_host_key_algorithm string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "server_host_key_algorithm length"}[:field_content] }},
        {:field_name => "encryption_algorithms_client_to_server length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "encryption_algorithms_client_to_server string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "encryption_algorithms_client_to_server length"}[:field_content] }},
        {:field_name => "encryption_algorithms_server_to_client length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "encryption_algorithms_server_to_client string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "encryption_algorithms_server_to_client length"}[:field_content] }},
        {:field_name => "mac_algorithms_client_to_server length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "mac_algorithms_client_to_server string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "mac_algorithms_client_to_server length"}[:field_content] }},
        {:field_name => "mac_algorithms_server_to_client length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "mac_algorithms_server_to_client string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "mac_algorithms_server_to_client length"}[:field_content] }},
        {:field_name => "compression_algorithms_client_to_server length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "compression_algorithms_client_to_server string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "compression_algorithms_client_to_server length"}[:field_content] }},
        {:field_name => "compression_algorithms_server_to_client length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "compression_algorithms_server_to_client string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "compression_algorithms_server_to_client length"}[:field_content] }},
        {:field_name => "languages_client_to_server length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "languages_client_to_server string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "languages_client_to_server length"}[:field_content] }},
        {:field_name => "languages_server_to_client length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "languages_server_to_client string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "languages_server_to_client length"}[:field_content] }},
        {:field_name => "First KEX Packet Follows", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Reserved", :field_size => 4, :field_type => :OCT_FIELD, :field_content => 0},
        {:field_name => "Padding String", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0,
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Padding length"}[:field_content] } },
    ]
end


def PrintECDHKeyExchangeInit()
    data_format = [
        {:field_name => "Packet length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Padding length", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Message Code", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "ECDH client's ephemeral public key length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "ECDH client's ephemeral public key (Q_C)", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0, 
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "ECDH client's ephemeral public key length"}[:field_content] }},
        {:field_name => "Padding String", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0,
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Padding length"}[:field_content] } },
    ]
end

def PrintECDHKeyExchangeReply()
    data_format = [
        {:field_name => "Packet length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Padding length", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Message Code", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Host key length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Host key type length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Host Key type string", :field_size => 0, :field_type => :STR_FIELD, :field_content => 0,
             :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Host key type length"}[:field_content] } },
        {:field_name => "Multi Precision Integer Length for e", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "RSA public exponent (e)", :field_size => 0, :field_type => :NUM_FIELD, :field_content => 0,
             :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Multi Precision Integer Length for e"}[:field_content] } },
        {:field_name => "Multi Precision Integer Length for n", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "RSA modulus (n)", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0,
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Multi Precision Integer Length for n"}[:field_content] } },
        {:field_name => "ECDH server's ephemeral public key length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "ECDH server's ephemeral public key (Q_S)", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0,
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "ECDH server's ephemeral public key length"}[:field_content] } },
        {:field_name => "KEX H signature length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "KEX H signature", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0,
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "KEX H signature length"}[:field_content] } },
        {:field_name => "Padding String", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0,
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Padding length"}[:field_content] } },
    ]
end


def PrintNewKeys()
    data_format = [
        {:field_name => "Packet length", :field_size => 4, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Padding length", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Message Code", :field_size => 1, :field_type => :NUM_FIELD, :field_content => 0},
        {:field_name => "Padding String", :field_size => 0, :field_type => :OCT_FIELD, :field_content => 0,
            :filed_update => ->() { data_format.detect{|item| item[:field_name] == "Padding length"}[:field_content] } },
    ]
end

@is_plain_data = false

def PrintServiceData(data, direction) 
    puts "PrintServiceData"
    output_str_ary = [
        "=======================================================================",
        ">> PrintServiceData  (%-15s) %s " % [@is_plain_data ? "PlainData" : "EncryptedData", direction],
        "-----------------------------------------------------------------------"]
    yield data.size if block_given?
    output_str_ary[1] += " [Total : %d bytes ] " % data.size
    output_str_ary += PrintFormatBinData(data, 16).AddIndentToStrs(" " * 4)
end

def DirectionString(is_to_server) 
    is_to_server ? "| Client ------> Server |" : "| Server ------> Client |"
end

@print_start_info = [
    :PrintSSHHello,
    :PrintSSHHello
]

@print_ary_by_msg_code = {
    20 => :PrintKeyExchangeInit,
    30 => :PrintECDHKeyExchangeInit,
    31 => :PrintECDHKeyExchangeReply,
    21 => :PrintNewKeys
}

@method_idx = 0
@output_to_file = []


def PrintSSHProcolDataDispatch(data, direction)
    output_str_ary = []
    method_sym = @print_ary_by_msg_code[data[5]]
    if method_sym == nil then
        output_str_ary += PrintServiceData(data, direction)
        yield data.size if block_given?
        return output_str_ary
    end
    data_format = send(@print_ary_by_msg_code[data[5]])
    puts method_sym.to_s
    output_str_ary = [
        "=======================================================================",
        ">> " + method_sym.to_s + "  " + direction, 
        "-----------------------------------------------------------------------"]
    output_str_ary += PrintDataByDataStructDescription(data_format, data)
    total_size = 0
    data_format.each do |item|
        total_size += item[:field_size]
    end
    yield total_size if block_given?
    output_str_ary[1] += " [Total : %d bytes ] " % total_size
    output_str_ary
end


def ParseSSHProtocolData(data_buf, is_send_to_server, log_idx)
    #data_buf.each do |item|
    #    puts item
    #end
    data_ary = []
    data_buf.each do |item|
        temp = item.split(/ /)
        temp.select! {|item| item =~ /[0-9a-fA-F][0-9a-fA-F]/ }
        temp.map! {|item| item.to_i(16) }
        data_ary += temp
    end

    puts "Total data size : " + data_ary.size.to_s
    data_remain = data_ary.size
    
    @output_to_file.push "\n======================= From Log line : %d ===========================" % log_idx
    while data_remain > 0
        begin
            if @method_idx < @print_start_info.size then
                @output_to_file += send(@print_start_info[@method_idx], data_ary, DirectionString(is_send_to_server)) do |data_size|
                                            puts "Parsed data size" + data_size.to_s
                                            data_remain -= data_size
                                            puts "Remained data size" + data_remain.to_s
                                        end
                @method_idx += 1
            else
                @output_to_file += PrintSSHProcolDataDispatch(data_ary, DirectionString(is_send_to_server)) do |data_size|
                    puts "Parsed data size" + data_size.to_s
                    data_remain -= data_size
                    puts "Remained data size" + data_remain.to_s
                end
            end
        rescue
            @output_to_file += PrintServiceData(data_ary, DirectionString(is_send_to_server)) do |data_size|
                puts "Parsed data size" + data_size.to_s
                data_remain -= data_size
                puts "Remained data size" + data_remain.to_s
            end
        end
        if data_remain > 0 then
            data_ary = data_ary[data_ary.size - data_remain, data_remain]
        end
    end
end



puts "Start Parsing!"

puts ARGV.size
ARGV.each {|item| puts item }

if ARGV.size >= 1 and ARGV[0] =~ /.*\.(txt|log)/
    log_file_list = [ARGV[0]]
else
    log_file_list = Dir["./*.txt"] + Dir["./*.log"]
end

log_file_list.each do | log_file_name |
    if log_file_name =~ /(.*)\.(txt|log)/
        f = File.new($1 + ".parsed", "w") 
        puts "Parsing #{$1}"
        is_transmit_data = false
        is_send = false
        data_buf = []
        data_log_index = 0
        @output_to_file = []
        @method_idx = 0
        File.open(log_file_name, "r") do |fh| 
            fh.each_line.with_index(1) do |line, index|
                if is_transmit_data && line =~ /(\[.*2017\]\s*)?(([0-9a-fA-F][0-9a-fA-F]\s*)+)/ then
                    if line =~ /(\[.*2017\]\s*)(.*)/ then
                        if $2 =~ /^(([0-9a-fA-F][0-9a-fA-F]\s*)+)/ then
                            data_buf.push $1
                        end
                    elsif line =~ /^(([0-9a-fA-F][0-9a-fA-F]\s*)+)/
                        data_buf.push $1
                    end
                elsif !data_buf.empty?
                    begin
                        ParseSSHProtocolData(data_buf, is_send, data_log_index)
                    rescue Exception => e
                        error_msg = "!!! Can't parse : %s, located in log file : %d " % [e.to_s, data_log_index]
                        puts error_msg
                        @output_to_file += [error_msg, "Parsing Result Missing!! Check the following"]
                    ensure
                        data_buf = []
                    end
                end

                begin
                    case line
                    when /.*UbloxSSHDataSendStart_PlainData.*/       then is_transmit_data = true; data_log_index = index; is_send = true; @is_plain_data = true
                    when /.*UbloxSSHDataSendStop_PlainData.*/       then is_transmit_data = false; data_log_index = index; 
                    when /.*UbloxSSHDataRecieveStart_PlainData.*/   then is_transmit_data = true; data_log_index = index; is_send = false; @is_plain_data = true
                    when /.*UbloxSSHDataRecieveStop_PlainData.*/    then is_transmit_data = false; data_log_index = index; 
                    when /.*UbloxSSHDataSendStart.*/                then is_transmit_data = true; data_log_index = index; is_send = true; @is_plain_data = false
                    when /.*UbloxSSHDataSendStop.*/                 then is_transmit_data = false
                    when /.*UbloxSSHDataRecieveStart.*/             then is_transmit_data = true; data_log_index = index; is_send = false; @is_plain_data = false
                    when /.*UbloxSSHDataRecieveStop.*/              then is_transmit_data = false
                    end
                rescue
                    puts " !!!!!!This line contains NON-ACSII code, line number : %d " % index
                end
            end
            @output_to_file.each do |line|
                f.print (line + "\n")
            end
            
        end
    end
end

