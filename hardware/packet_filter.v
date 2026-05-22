module packet_parser(
    input clk,
    input reset,
    input [31:0] src_ip,
    input [15:0] dest_port,
    input [7:0] protocol,
    input [7:0] pkt_count,
    output reg [1:0] attack_type,
    output reg [31:0] attacker_ip
);

// attack_type encoding:
// 00 = clean
// 01 = suspicious port
// 10 = port scan
// 11 = DDoS

reg [31:0] ip_table [0:4];
reg [7:0] count_table [0:4];
reg [7:0] new_count;
reg [2:0] i;
reg found;
reg [2:0] found_idx;
reg [2:0] replace_idx;

always @(posedge clk or posedge reset) begin
    if (reset) begin
        attack_type <= 2'b00;
        attacker_ip <= 0;
        new_count <= 0;
        replace_idx <= 0;
        for (i = 0; i < 5; i = i + 1) begin
            ip_table[i] <= 0;
            count_table[i] <= 0;
        end
    end
    else begin
        // default clean
        attack_type <= 2'b00;
        attacker_ip <= 0;

        // search table
        found = 0;
        found_idx = 0;
        for (i = 0; i < 5; i = i + 1) begin
            if (ip_table[i] == src_ip) begin
                found = 1;
                found_idx = i;
            end
        end

        if (found) begin
            new_count = count_table[found_idx] + 1;
            count_table[found_idx] <= new_count;

            // DDoS takes priority over port scan
            if (pkt_count > 100) begin
                attack_type <= 2'b11;
                attacker_ip <= src_ip;
            end
            else if (new_count > 5) begin
                attack_type <= 2'b10;
                attacker_ip <= src_ip;
            end
            else if (dest_port < 1024 && protocol == 8'h06) begin
                attack_type <= 2'b01;
                attacker_ip <= src_ip;
            end
        end
        else begin
            ip_table[replace_idx] <= src_ip;
            count_table[replace_idx] <= 1;
            replace_idx <= (replace_idx + 1) % 5;

            // still check suspicious even for new IPs
            if (dest_port < 1024 && protocol == 8'h06) begin
                attack_type <= 2'b01;
                attacker_ip <= src_ip;
            end
        end
    end
end

endmodule