
import streamlit as st
import pandas as pd
from datetime import datetime

# 1. PAGE SETUP AND EXISTING DARK THEME
st.set_page_config(
    page_title="NetCapture Pro",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
.stApp {background:#0b1020;color:#e8edf7}
[data-testid="stSidebar"] {background:#101827;border-right:1px solid #273449}
[data-testid="stHeader"] {background:#0b1020}
.block-container {max-width:1500px;padding-top:2rem}
[data-testid="stMetric"] {
    background:#151f33;border:1px solid #293750;
    border-radius:12px;padding:16px
}
[data-testid="stMetricLabel"] {color:#a9b8ce}
[data-testid="stMetricValue"] {color:#f5f8ff}
h1,h2,h3 {color:#f5f8ff}
.hero {
    background:linear-gradient(110deg,#14223a,#101827);
    border:1px solid #2b3c57;border-radius:16px;
    padding:25px;margin-bottom:22px
}
.panel {
    background:#121c2e;border:1px solid #293750;
    border-radius:12px;padding:18px;margin-bottom:12px
}
.section-label {color:#67d9ee;font-size:12px;letter-spacing:1.5px}
.hero-title {font-size:34px;font-weight:750;color:#f8fafc}
.hero-subtitle {color:#9db1cb;font-size:14px}
[data-testid="stDataFrame"] {border:1px solid #293750;border-radius:10px}
</style>
""", unsafe_allow_html=True)


# 2. COLUMN DETECTION
def find_column(df, candidates):
    lookup = {str(c).strip().lower(): c for c in df.columns}
    for name in candidates:
        if name.lower() in lookup:
            return lookup[name.lower()]
    return None


def get_columns(df):
    return {
        "number": find_column(df, ["No.", "No", "Frame Number", "frame.number"]),
        "time": find_column(df, ["Time", "frame.time", "Time (s)", "Timestamp"]),
        "source": find_column(df, ["Source", "ip.src", "Source Address"]),
        "destination": find_column(df, ["Destination", "ip.dst", "Destination Address"]),
        "protocol": find_column(df, ["Protocol", "_ws.col.Protocol", "protocol"]),
        "length": find_column(df, ["Length", "Packet Length", "frame.len"]),
        "info": find_column(df, ["Info", "_ws.col.Info", "Information"])
    }


# 3. EVIDENCE-BASED PRIVACY ASSESSMENT
def create_findings(df):
    cols = get_columns(df)
    protocol_col = cols["protocol"]

    output_columns = [
        "Priority", "Severity", "Finding", "Protocol",
        "Packet Rows", "Evidence", "Explanation", "Recommendation"
    ]

    if not protocol_col:
        return pd.DataFrame(columns=output_columns)

    protocols = (
        df[protocol_col].fillna("").astype(str)
        .str.strip().str.upper()
    )

    rules = {
        "HTTP": {
            "severity": "Review required",
            "finding": "HTTP traffic observed",
            "explanation": (
                "HTTP traffic may be unencrypted. The protocol label "
                "alone does not confirm sensitive data exposure."
            ),
            "action": (
                "Inspect the listed packets for visible request paths, "
                "headers or content. Use HTTPS for sensitive web traffic."
            )
        },
        "FTP": {
            "severity": "Review required",
            "finding": "FTP traffic observed",
            "explanation": (
                "Traditional FTP may expose commands or credentials "
                "because it does not encrypt the session."
            ),
            "action": (
                "Verify the service and inspect the packets. Consider "
                "SFTP or another appropriately secured transfer method."
            )
        },
        "TELNET": {
            "severity": "Review required",
            "finding": "Telnet traffic observed",
            "explanation": (
                "Traditional Telnet does not encrypt its session. "
                "The exported summary does not prove credential exposure."
            ),
            "action": (
                "Check whether the service is necessary. Prefer SSH "
                "for remote administration and restrict service access."
            )
        },
        "DNS": {
            "severity": "Informational",
            "finding": "DNS query metadata observed",
            "explanation": (
                "DNS packet summaries may reveal requested domain names. "
                "This is a metadata observation, not automatically a flaw."
            ),
            "action": (
                "Review DNS privacy requirements and resolver settings. "
                "Consider encrypted DNS where appropriate."
            )
        }
    }

    findings = []

    for protocol, rule in rules.items():
        matched = df.loc[protocols == protocol]
        if matched.empty:
            continue

        evidence = [f"{len(matched)} CSV row(s) labelled {protocol}"]

        if cols["number"]:
            ids = matched[cols["number"]].dropna().astype(str).head(10)
            if not ids.empty:
                evidence.append("Packet numbers: " + ", ".join(ids))

        for key, label in [("source", "Sources"), ("destination", "Destinations")]:
            if cols[key]:
                values = (
                    matched[cols[key]].dropna().astype(str)
                    .drop_duplicates().head(5).tolist()
                )
                if values:
                    evidence.append(label + ": " + ", ".join(values))

        if cols["info"]:
            samples = (
                matched[cols["info"]].dropna().astype(str)
                .drop_duplicates().head(3).tolist()
            )
            if samples:
                evidence.append("Packet summaries: " + " | ".join(samples))

        findings.append({
            "Priority": "Review",
            "Severity": rule["severity"],
            "Finding": rule["finding"],
            "Protocol": protocol,
            "Packet Rows": len(matched),
            "Evidence": "; ".join(evidence),
            "Explanation": rule["explanation"],
            "Recommendation": rule["action"]
        })

    return pd.DataFrame(findings, columns=output_columns)


# 4. ASSESSMENT REPORT GENERATOR
def prepare_report(df, findings):
    cols = get_columns(df)
    protocol_count = df[cols["protocol"]].nunique() if cols["protocol"] else 0

    lines = [
        "NETCAPTURE PRO",
        "Network Privacy Exposure Assessment",
        "=" * 48,
        f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Packet rows analyzed: {len(df)}",
        f"CSV columns: {len(df.columns)}",
        f"Distinct protocols: {protocol_count}",
        "",
        "ASSESSMENT FINDINGS",
        "=" * 48
    ]

    if findings.empty:
        lines.append("No configured protocol indicators were identified.")
    else:
        for _, item in findings.iterrows():
            lines.extend([
                "",
                f"Finding: {item['Finding']}",
                f"Priority: {item['Priority']}",
                f"Severity: {item['Severity']}",
                f"Protocol: {item['Protocol']}",
                f"Packet rows: {item['Packet Rows']}",
                f"Evidence: {item['Evidence']}",
                f"Explanation: {item['Explanation']}",
                f"Recommendation: {item['Recommendation']}"
            ])

    lines.extend([
        "",
        "METHODOLOGY AND LIMITATIONS",
        "=" * 48,
        "Analysis is based on rules applied to exported CSV fields.",
        "Packet row counts are not counts of confirmed security incidents.",
        "Protocol labels alone do not prove a vulnerability or data leak.",
        "This application does not decrypt TLS or inspect unavailable payloads.",
        "Verify packet references and conclusions in Wireshark.",
        "Results cover the uploaded capture only."
    ])

    return "\n".join(lines)


# 5. SIDEBAR AND FILE INPUT
with st.sidebar:
    st.markdown("##  NetCapture Pro")
    st.caption("NETWORK SECURITY WORKSPACE")
    st.divider()

    page = st.radio("NAVIGATION", [
        "Dashboard", "Traffic Analysis", "Privacy Findings",
        "Remediation", "Assessment Report"
    ])

    st.divider()
    st.markdown("#### Capture Input")
    uploaded_file = st.file_uploader(
        "Upload Wireshark CSV",
        type=["csv"],
        help="Upload a packet summary exported from Wireshark."
    )
    st.divider()
    st.caption("Local CSV analysis • Rule-based assessment")
    st.caption("Use only authorized packet captures.")


# 6. LOAD AND VALIDATE DATA
df = None

if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
        df.columns = df.columns.astype(str).str.strip()

        if df.empty:
            st.error("The uploaded CSV contains no packet rows.")
            st.stop()

        if not len(df.columns):
            st.error("The CSV contains no recognizable columns.")
            st.stop()

    except Exception as error:
        st.error(f"Could not read the CSV: {error}")
        st.stop()

cols = get_columns(df) if df is not None else {}
findings = create_findings(df) if df is not None else pd.DataFrame()


# 7. APPLICATION HEADER
st.markdown("""
<div class="hero">
    <div class="section-label">NETWORK TRAFFIC INTELLIGENCE</div>
    <div class="hero-title"> NetCapture Pro</div>
    <div class="hero-subtitle">
        Network visibility • Privacy assessment • Evidence-based findings
        • Remediation guidance
    </div>
</div>
""", unsafe_allow_html=True)


# 8. DASHBOARD
if page == "Dashboard":
    st.subheader("Dashboard Overview")

    if df is None:
        st.info("Upload a Wireshark CSV from the sidebar to begin.")
        a, b, c, d = st.columns(4)
        a.metric("Packets Analyzed", "—")
        b.metric("Privacy Indicators", "—")
        c.metric("Protocols Identified", "—")
        d.metric("Observed Addresses", "—")

        left, right = st.columns(2)
        with left:
            st.markdown("""
            <div class="panel"><h3> Traffic Intelligence</h3>
            Explore protocols, packet sizes and communicating addresses.</div>
            <div class="panel"><h3> Privacy Assessment</h3>
            Review observations with packet evidence and explanations.</div>
            """, unsafe_allow_html=True)
        with right:
            st.markdown("""
            <div class="panel"><h3> Remediation Centre</h3>
            Review practical recommendations for identified indicators.</div>
            <div class="panel"><h3> Assessment Report</h3>
            Export findings and assessment limitations.</div>
            """, unsafe_allow_html=True)

    else:
        addresses = []
        for key in ["source", "destination"]:
            if cols[key]:
                addresses.extend(df[cols[key]].dropna().astype(str).tolist())

        a, b, c, d = st.columns(4)
        a.metric("Packets Analyzed", f"{len(df):,}")
        b.metric("Privacy Indicators", len(findings))
        c.metric("Protocols Identified",
                 df[cols["protocol"]].nunique() if cols["protocol"] else 0)
        d.metric("Observed Addresses", len(set(addresses)))

        left, right = st.columns(2)
        with left:
            st.markdown("#### Protocol Distribution")
            if cols["protocol"]:
                st.bar_chart(df[cols["protocol"]].fillna("Unknown").value_counts())
            else:
                st.warning("Protocol column not found.")

        with right:
            st.markdown("#### Top Source Addresses")
            if cols["source"]:
                st.bar_chart(df[cols["source"]].value_counts().head(8))
            else:
                st.info("Source column not found.")

        if cols["length"]:
            lengths = pd.to_numeric(df[cols["length"]], errors="coerce").dropna()
            if not lengths.empty:
                a, b, c = st.columns(3)
                a.metric("Average Packet Length", f"{lengths.mean():.1f}")
                b.metric("Maximum Packet Length", f"{lengths.max():.0f}")
                c.metric("Minimum Packet Length", f"{lengths.min():.0f}")

        st.markdown("#### Recent Packet Records")
        st.dataframe(df.head(15), use_container_width=True, hide_index=True)
        st.caption("Observed addresses are CSV values, not verified device identities.")


# 9. TRAFFIC ANALYSIS
elif page == "Traffic Analysis":
    st.subheader(" Traffic Analysis")

    if df is None:
        st.info("Upload a Wireshark CSV to analyze traffic.")
    else:
        st.write(f"Packet rows loaded: **{len(df):,}**")

        if cols["protocol"]:
            summary = df[cols["protocol"]].fillna("Unknown").value_counts()
            st.markdown("#### Protocol Statistics")
            st.dataframe(summary.rename_axis("Protocol").reset_index(name="Packet Rows"),
                         use_container_width=True, hide_index=True)
            st.bar_chart(summary)

        left, right = st.columns(2)
        with left:
            if cols["source"]:
                st.markdown("#### Source Addresses")
                st.dataframe(df[cols["source"]].value_counts().head(15),
                             use_container_width=True)
        with right:
            if cols["destination"]:
                st.markdown("#### Destination Addresses")
                st.dataframe(df[cols["destination"]].value_counts().head(15),
                             use_container_width=True)

        if cols["length"]:
            lengths = pd.to_numeric(df[cols["length"]], errors="coerce").dropna()
            if not lengths.empty:
                st.markdown("#### Packet Length Distribution")
                st.bar_chart(lengths.value_counts().sort_index().head(30))

        st.markdown("#### Search Packet Records")
        query = st.text_input("Search CSV fields", placeholder="IP address, protocol or packet detail")

        if query:
            mask = df.astype(str).apply(
                lambda col: col.str.contains(query, case=False, regex=False, na=False)
            ).any(axis=1)
            st.dataframe(df.loc[mask].head(500), use_container_width=True, hide_index=True)
            st.caption(f"Matching rows: {int(mask.sum())}")
        else:
            st.dataframe(df.head(100), use_container_width=True, hide_index=True)


# 10. PRIVACY FINDINGS
elif page == "Privacy Findings":
    st.subheader(" Privacy Findings")
    st.caption("Rule-based observations supported by fields in the uploaded CSV.")

    if df is None:
        st.info("Upload a Wireshark CSV to inspect findings.")
    elif not cols["protocol"]:
        st.warning("No recognized Protocol column was found.")
    elif findings.empty:
        st.success("No configured protocol indicators were identified.")
        st.caption("This does not prove the capture is free of privacy risks.")
    else:
        priorities = st.multiselect(
            "Filter by review priority",
            ["Review", "Informational"],
            default=["Review", "Informational"]
        )
        visible = findings[findings["Priority"].isin(priorities)]
        st.dataframe(visible, use_container_width=True, hide_index=True)

        if not visible.empty:
            selected = st.selectbox("Inspect a finding", visible["Finding"].tolist())
            item = visible[visible["Finding"] == selected].iloc[0]

            st.markdown('<div class="panel">', unsafe_allow_html=True)
            st.markdown(f"**{item['Finding']}**")
            st.write(f"Priority: **{item['Priority']}**")
            st.write(f"Severity: **{item['Severity']}**")
            st.write(f"Protocol: **{item['Protocol']}**")
            st.write(f"Matching packet rows: **{item['Packet Rows']}**")
            st.write(f"**Evidence:** {item['Evidence']}")
            st.write(f"**Why it matters:** {item['Explanation']}")
            st.write(f"**Recommended action:** {item['Recommendation']}")
            st.markdown("</div>", unsafe_allow_html=True)

        st.warning("Verify the referenced packets in Wireshark before concluding that exposure occurred.")


# 11. REMEDIATION
elif page == "Remediation":
    st.subheader(" Remediation Centre")

    if df is None:
        st.info("Upload a capture to see recommendations based on its findings.")
    elif findings.empty:
        st.info("No configured indicators were identified. This does not prove the capture is risk-free.")
    else:
        for _, item in findings.iterrows():
            with st.expander(f"{item['Priority']} | {item['Finding']}"):
                st.write(f"**Evidence:** {item['Evidence']}")
                st.write(f"**Why it matters:** {item['Explanation']}")
                st.write(f"**Recommended action:** {item['Recommendation']}")

    st.markdown("#### General Security Guidance")
    with st.expander("Web communication"):
        st.write("Inspect HTTP packet details and use HTTPS for sensitive web communications.")
    with st.expander("File transfer and remote administration"):
        st.write("Verify whether FTP or Telnet is required; consider SFTP and SSH where appropriate.")
    with st.expander("DNS privacy"):
        st.write("Review DNS resolver settings. Encrypted DNS may protect DNS queries but does not hide all network metadata.")
    with st.expander("Capture handling"):
        st.write("Restrict access to packet captures because they may contain sensitive metadata or unencrypted content.")


# 12. ASSESSMENT REPORT
elif page == "Assessment Report":
    st.subheader(" Assessment Report")

    if df is None:
        st.info("Upload a Wireshark CSV to generate a report.")
    else:
        a, b, c = st.columns(3)
        a.metric("Packet Rows", f"{len(df):,}")
        b.metric("Distinct Protocols",
                 df[cols["protocol"]].nunique() if cols["protocol"] else 0)
        c.metric("Indicators", len(findings))

        st.markdown("#### Findings Included")
        if findings.empty:
            st.info("No configured indicators were identified.")
        else:
            st.dataframe(findings, use_container_width=True, hide_index=True)

        report = prepare_report(df, findings)
        st.download_button(
            " Download Text Assessment Report",
            data=report,
            file_name="netcapture_pro_report.txt",
            mime="text/plain",
            use_container_width=True
        )

        if not findings.empty:
            st.download_button(
                " Export Findings as CSV",
                data=findings.to_csv(index=False).encode("utf-8"),
                file_name="netcapture_pro_findings.csv",
                mime="text/csv",
                use_container_width=True
            )

        st.caption("Findings are indicators, not confirmed vulnerabilities. Validate them in Wireshark.")
