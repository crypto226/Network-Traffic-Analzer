import streamlit as st
import plotly.express as px
import pandas as pd
from scapy.all import sniff, TCP, UDP, ICMP, IP, get_if_list
import threading
import time
from collections import deque
import socket
import requests

# ----------------------------
# Shared data storage
# ----------------------------
packet_data = deque(maxlen=200)  # recent packet stats
stats = {"packets": 0, "tcp_packets": 0, "udp_packets": 0, "icmp_packets": 0, "retransmissions": 0}
time_series = []  # store history of stats

# ----------------------------
# IP Enrichment (Country, Org, City, Lat, Lon) with fallback
# ----------------------------
ip_cache = {}

def resolve_ip_info(ip):
    if ip in ip_cache:
        return ip_cache[ip]

    try:
        # First try ip-api.com
        url = f"http://ip-api.com/json/{ip}"
        resp = requests.get(url, timeout=3).json()
        if resp["status"] == "success" and resp.get("city") != "Unknown":
            info = {
                "country": resp.get("country", "Unknown"),
                "org": resp.get("org", "Unknown"),
                "city": resp.get("city", "Unknown"),
                "latitude": resp.get("lat", "N/A"),
                "longitude": resp.get("lon", "N/A"),
                "ip": ip
            }
        else:
            # Fallback to ipinfo.io (requires API key)
            url = f"https://ipinfo.io/{ip}/json?token=YOUR_API_KEY"
            resp = requests.get(url, timeout=3).json()
            info = {
                "country": resp.get("country", "Unknown"),
                "org": resp.get("org", "Unknown"),
                "city": resp.get("city", "Unknown"),
                "latitude": resp.get("loc", "N/A").split(",")[0] if "loc" in resp else "N/A",
                "longitude": resp.get("loc", "N/A").split(",")[1] if "loc" in resp else "N/A",
                "ip": ip
            }
    except Exception as e:
        info = {
            "country": "Lookup failed",
            "org": "N/A",
            "city": "N/A",
            "latitude": "N/A",
            "longitude": "N/A",
            "ip": ip
        }

    ip_cache[ip] = info
    return info

# ----------------------------
# Resolve IP -> Hostname
# ----------------------------
def resolve_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return ip  # fallback if no hostname found

# ----------------------------
# Packet capture callback
# ----------------------------
def packet_callback(packet):
    stats["packets"] += 1

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src = resolve_hostname(src_ip)
        dst = resolve_hostname(dst_ip)

        if TCP in packet:
            stats["tcp_packets"] += 1
            seq = packet[TCP].seq
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            key = (f"{src}:{sport}", f"{dst}:{dport}", seq, src_ip, dst_ip, "TCP")

            if key in packet_data:
                stats["retransmissions"] += 1

            packet_data.append(key)

        elif UDP in packet:
            stats["udp_packets"] += 1
            key = (f"{src}:{packet[UDP].sport}", f"{dst}:{packet[UDP].dport}", "UDP", src_ip, dst_ip, "UDP")
            packet_data.append(key)

        elif ICMP in packet:
            stats["icmp_packets"] += 1
            key = (src, dst, "ICMP", src_ip, dst_ip, "ICMP")
            packet_data.append(key)

# ----------------------------
# Background sniffing thread
# ----------------------------
def start_sniffing(iface):
    sniff(prn=packet_callback, iface=iface, store=False)

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
st.title("Network Traffic Analyzer")

# Get list of interfaces
interfaces = get_if_list()
iface = st.selectbox("Select network interface:", interfaces)

start_button = st.button("Start Capture")

if start_button:
    st.success(f"Sniffing started on interface: {iface}")
    t = threading.Thread(target=start_sniffing, args=(iface,), daemon=True)
    t.start()

    placeholder = st.empty()
    start_time = time.time()
    chart_counter = 0  # Initialize counter for unique keys

    while True:
        time.sleep(1)

        # Record per-second stats
        elapsed = int(time.time() - start_time)
        time_series.append({
            "time": elapsed,
            "packets": stats["packets"],
            "tcp_packets": stats["tcp_packets"],
            "udp_packets": stats["udp_packets"],
            "icmp_packets": stats["icmp_packets"],
            "retransmissions": stats["retransmissions"]
        })
        df_time = pd.DataFrame(time_series)

        with placeholder.container():
            # Metrics row
            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("Total Packets", stats["packets"])
            col2.metric("TCP Packets", stats["tcp_packets"])
            col3.metric("UDP Packets", stats["udp_packets"])
            col4.metric("ICMP Packets", stats["icmp_packets"])
            col5.metric("Retransmissions", stats["retransmissions"])

            # 📊 Top Talkers Table with Geo Info and highlighting
            if len(packet_data) > 0:
                df_recent = pd.DataFrame(list(packet_data),
                                        columns=["Source", "Destination", "Protocol/Seq", "src_ip", "dst_ip", "proto"])
                df_recent["Source_Info"] = df_recent["src_ip"].apply(
                    lambda x: f"{resolve_ip_info(x)['country']} | {resolve_ip_info(x)['city']} | {resolve_ip_info(x)['org']}"
                )
                df_recent["Destination_Info"] = df_recent["dst_ip"].apply(
                    lambda x: f"{resolve_ip_info(x)['country']} | {resolve_ip_info(x)['city']} | {resolve_ip_info(x)['org']}"
                )
                df_recent["Source_Lat"] = df_recent["src_ip"].apply(lambda x: resolve_ip_info(x)["latitude"])
                df_recent["Source_Lon"] = df_recent["src_ip"].apply(lambda x: resolve_ip_info(x)["longitude"])
                df_recent["Dest_Lat"] = df_recent["dst_ip"].apply(lambda x: resolve_ip_info(x)["latitude"])
                df_recent["Dest_Lon"] = df_recent["dst_ip"].apply(lambda x: resolve_ip_info(x)["longitude"])

                st.subheader("Top Talkers (with Country, City, Org)")
                # Highlight rows with "Unknown" in Source or Destination Info
                styled_df = df_recent[["Source", "Source_Info", "Destination", "Destination_Info", "proto"]].tail(20).style.apply(
                    lambda x: ['background-color:#000000' if "Unknown" in str(x['Source_Info']) or "Unknown" in str(x['Destination_Info']) else '' for _ in x],
                    axis=1
                )
                st.dataframe(styled_df, use_container_width=True)

                # 🌍 Top Countries/Orgs
                country_counts = df_recent["Source_Info"].value_counts().reset_index()
                country_counts.columns = ["Country | City | Org", "Packets"]
                fig_country = px.bar(country_counts.head(10), x="Country | City | Org", y="Packets",
                                    title="🌍 Top Countries/Cities/Orgs by Traffic")
                st.plotly_chart(fig_country, use_container_width=True, key=f"bar-{chart_counter}")

                # 📍 Optional: Map visualization of IPs
                map_data = pd.DataFrame()
                if not df_recent[["Source_Lat", "Source_Lon"]].dropna().empty:
                    map_data = pd.concat([
                        df_recent[["Source_Lat", "Source_Lon", "Source_Info"]].rename(
                            columns={"Source_Lat": "lat", "Source_Lon": "lon", "Source_Info": "Info"}
                        ),
                        df_recent[["Dest_Lat", "Dest_Lon", "Destination_Info"]].rename(
                            columns={"Dest_Lat": "lat", "Dest_Lon": "lon", "Destination_Info": "Info"}
                        )
                    ]).dropna()
                    if not map_data.empty:
                        fig_map = px.scatter_geo(
                            map_data,
                            lat="lat",
                            lon="lon",
                            hover_name="Info",
                            title="🌍 IP Geolocation Map",
                            projection="natural earth"
                        )
                        st.plotly_chart(fig_map, use_container_width=True, key=f"map-{chart_counter}")

            # 📈 Line chart of packets over time
            if not df_time.empty:
                fig = px.line(df_time, x="time",
                              y=["packets", "tcp_packets", "udp_packets", "icmp_packets", "retransmissions"],
                              title="Traffic Trend Over Time")
                st.plotly_chart(fig, use_container_width=True, key=f"line-{chart_counter}")

            # 🥧 Pie chart of protocol distribution
            proto_counts = {
                "TCP": stats["tcp_packets"],
                "UDP": stats["udp_packets"],
                "ICMP": stats["icmp_packets"]
            }
            df_proto = pd.DataFrame(list(proto_counts.items()), columns=["Protocol", "Count"])
            fig_pie = px.pie(df_proto, values="Count", names="Protocol", title="Protocol Distribution")
            st.plotly_chart(fig_pie, use_container_width=True, key=f"pie-{chart_counter}")

            chart_counter += 1  # Increment counter for next iteration








