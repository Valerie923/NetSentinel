"""
simulate_verilog_output.py
Simulates the hardware packet_parser Verilog module output in Python.
Mirrors the exact logic of packet_filter.v for software-layer testing.

Attack type encoding (matches Verilog):
  00 = clean
  01 = suspicious port
  10 = port scan
  11 = DDoS
"""

import random
import time

# Mirror Verilog module state
ip_table = [0] * 5
count_table = [0] * 5
replace_idx = 0


def reset():
    """Reset all state — mirrors Verilog reset signal"""
    global ip_table, count_table, replace_idx
    ip_table = [0] * 5
    count_table = [0] * 5
    replace_idx = 0


def int_to_ip(ip_int):
    """Convert 32-bit integer to human-readable IP string"""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def ip_to_int(ip_str):
    """Convert IP string to 32-bit integer"""
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def process_packet(src_ip_int, dest_port, protocol, pkt_count):
    """
    Mirrors the Verilog always @(posedge clk) block.
    Returns (attack_type, attacker_ip_int)
    """
    global ip_table, count_table, replace_idx

    attack_type = 0b00
    attacker_ip = 0

    # Search table for src_ip
    found = False
    found_idx = 0
    for i in range(5):
        if ip_table[i] == src_ip_int:
            found = True
            found_idx = i
            break

    if found:
        new_count = count_table[found_idx] + 1
        count_table[found_idx] = new_count

        # DDoS takes priority (mirrors Verilog priority chain)
        if pkt_count > 100:
            attack_type = 0b11
            attacker_ip = src_ip_int
        elif new_count > 5:
            attack_type = 0b10
            attacker_ip = src_ip_int
        elif dest_port < 1024 and protocol == 0x06:
            attack_type = 0b01
            attacker_ip = src_ip_int
    else:
        # New IP — add to table with FIFO eviction
        ip_table[replace_idx] = src_ip_int
        count_table[replace_idx] = 1
        replace_idx = (replace_idx + 1) % 5

        if dest_port < 1024 and protocol == 0x06:
            attack_type = 0b01
            attacker_ip = src_ip_int

    return attack_type, attacker_ip


ATTACK_LABELS = {
    0b00: "Clean",
    0b01: "Suspicious Port",
    0b10: "Port Scan",
    0b11: "DDoS"
}


def generate_traffic(n=50):
    """
    Generate a mix of clean and malicious simulated packets.
    Returns list of packet dicts with hardware output fields.
    """
    reset()
    packets = []

    attacker_a = ip_to_int("192.168.0.1")
    attacker_b = ip_to_int("10.0.0.5")
    clean_ip = ip_to_int("172.16.0.1")

    for i in range(n):
        # Mix of traffic types
        roll = random.random()

        if roll < 0.3:
            # Port scan from attacker A
            src_ip = attacker_a
            dest_port = random.choice([21, 22, 23, 25, 80, 443, 3306, 8080, i % 1024])
            protocol = 0x06
            pkt_count = 1
        elif roll < 0.5:
            # DDoS from attacker B
            src_ip = attacker_b
            dest_port = 80
            protocol = 0x06
            pkt_count = random.randint(101, 200)
        elif roll < 0.7:
            # Suspicious port hit
            src_ip = ip_to_int(f"10.0.{random.randint(0,255)}.{random.randint(1,254)}")
            dest_port = random.choice([22, 23, 25, 21])
            protocol = 0x06
            pkt_count = 1
        else:
            # Clean traffic
            src_ip = clean_ip
            dest_port = random.randint(1024, 65535)
            protocol = 0x06
            pkt_count = 1

        attack_type, attacker_ip = process_packet(src_ip, dest_port, protocol, pkt_count)

        packets.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "src_ip": int_to_ip(src_ip),
            "dest_port": dest_port,
            "protocol": "TCP" if protocol == 0x06 else "UDP",
            "pkt_count": pkt_count,
            "attack_type": attack_type,
            "attack_label": ATTACK_LABELS[attack_type],
            "attacker_ip": int_to_ip(attacker_ip) if attacker_ip else "-"
        })

    return packets


if __name__ == "__main__":
    print("NetSentinel — Verilog Hardware Layer Simulation")
    print("=" * 60)
    packets = generate_traffic(20)
    for p in packets:
        print(f"[{p['timestamp']}] {p['src_ip']:<16} port={p['dest_port']:<6} "
              f"→ {p['attack_label']:<20} attacker={p['attacker_ip']}")