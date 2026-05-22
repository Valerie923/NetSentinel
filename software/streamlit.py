"""
dashboard.py
NetSentinel — Real-time Network Threat Detection Dashboard
Streamlit frontend that visualises hardware packet filter output
and ML classification results.

Run with: streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import time
import random
from simulate_verilog_output import generate_traffic, ATTACK_LABELS
from ml_classifier import predict

# Page config
st.set_page_config(
    page_title="NetSentinel",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ NetSentinel")
st.caption("FPGA-Inspired Hardware Packet Filter · Real-Time Network Threat Detection")
st.divider()

# Sidebar controls
with st.sidebar:
    st.header("⚙️ Controls")
    n_packets = st.slider("Packets to simulate", 10, 200, 50)
    refresh_rate = st.slider("Refresh rate (seconds)", 1, 10, 3)
    auto_refresh = st.toggle("Auto refresh", value=False)
    run_button = st.button("▶ Run Simulation", use_container_width=True)
    st.divider()
    st.markdown("**Attack Type Legend**")
    st.markdown("🟢 `00` Clean")
    st.markdown("🟡 `01` Suspicious Port")
    st.markdown("🟠 `10` Port Scan")
    st.markdown("🔴 `11` DDoS")

# Generate traffic
if run_button or auto_refresh:
    packets = generate_traffic(n_packets)

    # Add ML predictions
    for p in packets:
        _, ml_label, confidence = predict(p)
        p["ml_label"] = ml_label
        p["confidence"] = confidence

    df = pd.DataFrame(packets)

    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    total = len(df)
    ddos = len(df[df["attack_type"] == 0b11])
    port_scan = len(df[df["attack_type"] == 0b10])
    suspicious = len(df[df["attack_type"] == 0b01])
    clean = len(df[df["attack_type"] == 0b00])

    col1.metric("Total Packets", total)
    col2.metric("🔴 DDoS", ddos)
    col3.metric("🟠 Port Scans", port_scan)
    col4.metric("🟡 Suspicious", suspicious)

    st.divider()

    # Attack distribution chart
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("Attack Distribution")
        dist = df["attack_label"].value_counts().reset_index()
        dist.columns = ["Attack Type", "Count"]
        st.bar_chart(dist.set_index("Attack Type"))

    with col_right:
        st.subheader("Top Attacking IPs")
        attackers = df[df["attacker_ip"] != "-"]["attacker_ip"].value_counts().head(5).reset_index()
        attackers.columns = ["IP Address", "Detections"]
        st.dataframe(attackers, use_container_width=True, hide_index=True)

    st.divider()

    # Live packet feed
    st.subheader("📡 Packet Feed")

    def color_attack(val):
        colors = {
            "Clean": "background-color: #d4edda",
            "Suspicious Port": "background-color: #fff3cd",
            "Port Scan": "background-color: #ffe5d0",
            "DDoS": "background-color: #f8d7da"
        }
        return colors.get(val, "")

    display_df = df[[
        "timestamp", "src_ip", "dest_port",
        "protocol", "pkt_count", "attack_label",
        "attacker_ip", "ml_label", "confidence"
    ]].rename(columns={
        "timestamp": "Time",
        "src_ip": "Source IP",
        "dest_port": "Port",
        "protocol": "Protocol",
        "pkt_count": "Pkt Count",
        "attack_label": "HW Detection",
        "attacker_ip": "Attacker IP",
        "ml_label": "ML Classification",
        "confidence": "Confidence %"
    })

    st.dataframe(
        display_df.style.applymap(color_attack, subset=["HW Detection"]),
        use_container_width=True,
        hide_index=True
    )

    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()

else:
    st.info("👈 Click **Run Simulation** in the sidebar to start NetSentinel")
    st.markdown("""
    ### How NetSentinel Works
    
    ```
    Network Traffic
         │
         ▼
    ┌─────────────────────────────┐
    │  Verilog Hardware Filter    │  ← packet_filter.v
    │  • Kernel-bypass inspection │
    │  • 5-IP simultaneous track  │
    │  • 2-bit attack_type output │
    └──────────────┬──────────────┘
                   │ attack_type + attacker_ip
                   ▼
    ┌─────────────────────────────┐
    │  Python ML Classifier       │  ← ml_classifier.py
    │  • Random Forest model      │
    │  • Confidence scoring       │
    └──────────────┬──────────────┘
                   │
                   ▼
    ┌─────────────────────────────┐
    │  Streamlit Dashboard        │  ← dashboard.py
    │  • Real-time threat feed    │
    │  • Attack distribution      │
    │  • Top attacker IPs         │
    └─────────────────────────────┘
    ```
    """)