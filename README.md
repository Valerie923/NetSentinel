# NetSentinel 🛡️

A hardware-based network intrusion detection system that monitors and classifies network attacks in real time — built in Verilog with a Python dashboard on top.

---

## What it does

Most firewalls run on software, on the same OS they're trying to protect. NetSentinel pushes detection down to the hardware level, so attacks are caught before the operating system even sees them.

It monitors incoming packets and classifies them into:

| Code | Attack Type |
|------|-------------|
| `00` | Clean traffic |
| `01` | Port scan |
| `10` | DDoS attempt |
| `11` | Severe / combined attack |

A Python dashboard sits on top, logging flagged IPs, attack types, and timestamps in real time.

---

## How it works

```
Incoming packets
      │
      ▼
 Verilog FSM  ──── classifies attack ──── 2-bit output
      │
      ▼
 Python layer ──── reads output ──── live dashboard + IP log
```

The core logic is a **finite state machine** in Verilog that tracks packet frequency, source IPs, and port patterns. When thresholds are crossed, it raises an attack signal that Python picks up and displays.

---

## Tech stack

- **Verilog** — hardware detection logic & state machine
- **Python** — dashboard, IP logging, attack timeline

---

## Project structure

```
NetSentinel/
├── src/
│   └── netsentinel.v      # Verilog FSM — core detection logic
├── sim/
│   └── testbench.v        # Simulation testbench
├── dashboard/
│   └── monitor.py         # Python dashboard
└── README.md
```

---

## Running it

**Simulate the Verilog:**
```bash
iverilog -o netsentinel sim/testbench.v src/netsentinel.v
vvp netsentinel
```

**Run the dashboard:**
```bash
python dashboard/monitor.py
```

---

## What's next

- Brute force detection
- Automatic IP blocking at the hardware level
- Deploy on a real FPGA board

---

## Built by

Solo project built for a hackathon. Hardware security from first principles.
