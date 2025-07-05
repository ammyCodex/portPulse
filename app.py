import streamlit as st
import socket
import pandas as pd
import json
import time
import numpy as np
from censys.search import CensysHosts
from sklearn.ensemble import RandomForestClassifier
import plotly.graph_objects as go

# --- ML Model Training (Synthetic example)
@st.cache_data(show_spinner=False)
def train_model():
    np.random.seed(42)
    X = []
    y = []
    for _ in range(1000):
        total_ports = np.random.randint(20, 200)
        open_ports = np.random.randint(0, total_ports+1)
        ratio = open_ports / total_ports
        X.append([open_ports, ratio, total_ports])
        if ratio > 0.3:
            y.append(2)
        elif ratio > 0.1:
            y.append(1)
        else:
            y.append(0)
    X = np.array(X)
    y = np.array(y)
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)
    return model

model = train_model()

# TCP connect scan using socket
def tcp_connect_scan(target_ip, ports, progress_bar, status_text, timeout=0.5):
    open_ports = []
    total = len(ports)
    for i, port in enumerate(ports):
        status_text.markdown(f"<span class='scan-status'>TCP Connect scan: Scanning port <b>{port}</b> ({i+1}/{total})...</span>", unsafe_allow_html=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target_ip, port))
            open_ports.append(port)
        except:
            pass
        finally:
            sock.close()
        progress_bar.progress((i+1)/total)
    return open_ports

# Censys enrichment
def fetch_censys_data(ip, api_id, api_secret):
    try:
        client = CensysHosts(api_id=api_id, api_secret=api_secret)
        results = client.search(f'ip: {ip}', per_page=1)
        if results and results["hits"]:
            hit = results["hits"][0]
            return {
                "ip": hit.get("ip", "N/A"),
                "location": hit.get("location", {}),
                "services": hit.get("services", [])
            }
        return {"note": "No data found."}
    except Exception as e:
        return {"error": str(e)}

# Plot network node style visualization
def plot_network_map(ip, open_ports, risk_level):
    risk_colors = {"✅ Low Risk": "green", "⚠️ Medium Risk": "orange", "🔥 High Risk": "red"}
    node_color = risk_colors.get(risk_level, "gray")

    nodes = [ip] + [f"Port {p}" for p in open_ports]

    angle_step = 360 / max(len(open_ports), 1)
    node_x = [0]
    node_y = [0]

    for i in range(len(open_ports)):
        angle_deg = i * angle_step
        angle_rad = angle_deg * (np.pi / 180)
        node_x.append(3 * np.cos(angle_rad))
        node_y.append(3 * np.sin(angle_rad))

    edge_x = []
    edge_y = []
    for i in range(1, len(nodes)):
        edge_x.extend([node_x[0], node_x[i], None])
        edge_y.extend([node_y[0], node_y[i], None])

    fig = go.Figure()

    fig.add_trace(go.Scatter(x=edge_x, y=edge_y,
                             mode='lines',
                             line=dict(color='lightgreen', width=1),
                             hoverinfo='none'))

    fig.add_trace(go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        marker=dict(size=30, color=[node_color] + ['#00ff41']*len(open_ports), line=dict(width=2, color='darkgreen')),
        text=nodes,
        textposition="bottom center",
        hoverinfo='text'
    ))

    fig.update_layout(
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, visible=False),
        yaxis=dict(showgrid=False, zeroline=False, visible=False),
        plot_bgcolor='#0f1218',
        paper_bgcolor='#0f1218',
        margin=dict(l=20, r=20, t=20, b=20),
        height=450
    )
    st.plotly_chart(fig, use_container_width=True)

# Styling
def hacking_css():
    st.markdown("""
    <style>
    body, .main {
        background-color: #0f1218;
        color: #00ff41;
        font-family: 'Courier New', Courier, monospace;
    }
    h1, h2, h3 {
        color: #00ff41;
        text-shadow: 0 0 10px #00ff41;
    }
    .scan-status {
        animation: blink 1.5s step-start 0s infinite;
        color: #39ff14;
    }
    @keyframes blink {
        50% { opacity: 0; }
    }
    div.stButton > button {
        background: linear-gradient(90deg, #00ff41, #007700);
        color: #000;
        font-weight: bold;
        border-radius: 8px;
        padding: 0.6em 1.2em;
        box-shadow: 0 0 10px #00ff41;
        transition: all 0.3s ease;
    }
    div.stButton > button:hover {
        background: linear-gradient(90deg, #007700, #00ff41);
        box-shadow: 0 0 20px #00ff41;
        color: #fff;
        cursor: pointer;
    }
    .stDataFrame table {
        border-collapse: collapse;
        border: 1px solid #00ff41;
    }
    .stDataFrame th, .stDataFrame td {
        border: 1px solid #00ff41 !important;
        padding: 0.5em !important;
        color: #00ff41 !important;
        background-color: #001100 !important;
    }
    button[title="Download"] {
        background-color: #00ff41 !important;
        color: #000 !important;
        font-weight: bold !important;
        border-radius: 6px !important;
        box-shadow: 0 0 8px #00ff41 !important;
        transition: all 0.3s ease !important;
    }
    button[title="Download"]:hover {
        background-color: #007700 !important;
        color: #fff !important;
        box-shadow: 0 0 16px #00ff41 !important;
    }
    ::-webkit-scrollbar {
        width: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #001100;
    }
    ::-webkit-scrollbar-thumb {
        background: #00ff41;
        border-radius: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

hacking_css()

st.set_page_config(page_title="portPulse 🔍", page_icon="🛡️", layout="centered")

st.markdown("<h1 style='text-align:center;'>portPulse 🔍</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align:center; color:#39ff14; font-style: italic;'>AI Powered TCP Connect Port Scanner</h3>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; color:#39ff14;'>Scan, analyze & uncover hidden network secrets</p>", unsafe_allow_html=True)

target_ip = st.text_input("Enter target IP address or domain:", "scanme.nmap.org")
port_range = st.text_input("Enter ports or range (e.g., 20-80, 443, 8080):", "20-80")
censys_id = st.text_input("Censys API ID:", type="password")
censys_secret = st.text_input("Censys API Secret:", type="password")

if st.button("Start TCP Connect Scan 🔎"):
    try:
        ports = []
        for part in port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end+1))
            else:
                ports.append(int(part))

        st.info(f"Starting scan on {target_ip} for {len(ports)} ports...")

        progress_bar = st.progress(0)
        status_text = st.empty()

        start_time = time.time()
        open_ports = tcp_connect_scan(target_ip, ports, progress_bar, status_text)
        duration = time.time() - start_time

        st.success(f"Scan done in {duration:.2f} seconds. Open ports: {open_ports}")

        open_ports_count = len(open_ports)
        total_ports = len(ports)
        ratio = open_ports_count / total_ports
        features = [[open_ports_count, ratio, total_ports]]
        pred = model.predict(features)[0]
        risk_map = {0: "✅ Low Risk", 1: "⚠️ Medium Risk", 2: "🔥 High Risk"}
        risk_level = risk_map[pred]
        risk_color = "green" if pred == 0 else "orange" if pred == 1 else "red"

        st.markdown(f"<h2 style='color:{risk_color}; text-align:center;'>Overall AI Vulnerability Risk: {risk_level}</h2>", unsafe_allow_html=True)

        df_ports = pd.DataFrame({"Open Ports": open_ports})
        st.dataframe(df_ports.style.set_properties(**{'color': '#00ff41', 'background-color': '#001100'}), height=200)

        # Censys enrichment
        if censys_id and censys_secret:
            st.markdown("## 🌐 Censys Intelligence")
            censys_info = fetch_censys_data(target_ip, censys_id, censys_secret)
            if "error" in censys_info:
                st.error(f"Censys error: {censys_info['error']}")
            else:
                loc = censys_info.get("location", {})
                st.markdown(f"**IP:** {censys_info.get('ip', 'N/A')}")
                st.markdown(f"**City:** {loc.get('city', 'N/A')} ({loc.get('country', 'N/A')})")
                st.markdown(f"**Services Found:** {len(censys_info.get('services', []))}")
                for svc in censys_info.get("services", []):
                    st.markdown(f"**Port {svc.get('port')}:** {svc.get('service_name', 'unknown')} | Protocol: {svc.get('transport_protocol', '')}")
        else:
            st.info("Censys API ID and Secret not provided. Skipping Censys enrichment.")

        # Show network map visualization
        if open_ports:
            plot_network_map(target_ip, open_ports, risk_level)
        else:
            st.info("No open ports found to display on network map.")

        export_data = {
            "target_ip": target_ip,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": open_ports,
            "duration_sec": duration,
            "ai_risk_level": risk_level
        }

        st.download_button("Download Scan JSON 📥", json.dumps(export_data, indent=2), file_name="portpulse_scan.json")
        st.download_button("Download Scan CSV 📥", df_ports.to_csv(index=False), file_name="portpulse_scan.csv")

    except Exception as e:
        st.error(f"Oops! Something went wrong:\n{e}")

st.markdown("<hr><p style='text-align:center; font-size: 0.8em; color:#00ff41;'>Developed by portPulse Team 🚀</p>", unsafe_allow_html=True)
