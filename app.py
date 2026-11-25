import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import tempfile
import os

from detector import detect_anomalies


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="LogSentinel AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# COMPLETE CSS FIX
# ============================================================

st.markdown("""
<style>

/* Main application background */
.stApp {
    background-color: #0b1120 !important;
    color: #f1f5f9 !important;
}

/* Main content */
section.main {
    background-color: #0b1120 !important;
}

/* Text visibility */
.stApp p,
.stApp span,
.stApp label,
.stApp li,
.stApp div,
.stApp small {
    color: #e2e8f0;
}

/* Headings */
h1, h2, h3, h4, h5, h6 {
    color: #f8fafc !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #111827 !important;
    border-right: 1px solid #263449 !important;
}

section[data-testid="stSidebar"] * {
    color: #f1f5f9 !important;
}

/* Sidebar radio buttons */
section[data-testid="stSidebar"] div[role="radiogroup"] label {
    background-color: #172235 !important;
    border: 1px solid #263449 !important;
    border-radius: 10px !important;
    padding: 8px 12px !important;
    margin-bottom: 5px !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
    background-color: #24344b !important;
}

/* Radio button text */
section[data-testid="stSidebar"] div[role="radiogroup"] p {
    color: #ffffff !important;
}

/* File uploader */
[data-testid="stFileUploader"] {
    background-color: #111c2e !important;
    border: 2px dashed #38bdf8 !important;
    border-radius: 14px !important;
    padding: 12px !important;
}

[data-testid="stFileUploader"] section {
    background-color: #111c2e !important;
}

[data-testid="stFileUploader"] button {
    background-color: #0284c7 !important;
    color: white !important;
    border: none !important;
}

[data-testid="stFileUploader"] small {
    color: #e2e8f0 !important;
}

[data-testid="stFileUploader"] span {
    color: #e2e8f0 !important;
}

/* Uploaded file information */
[data-testid="stFileUploaderFile"] {
    background-color: #1e293b !important;
    border-radius: 8px !important;
}

[data-testid="stFileUploaderFile"] * {
    color: #ffffff !important;
}

/* Buttons */
.stButton button,
.stDownloadButton button {
    background-color: #0284c7 !important;
    color: #ffffff !important;
    border: 1px solid #38bdf8 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
}

.stButton button:hover,
.stDownloadButton button:hover {
    background-color: #0369a1 !important;
    border-color: #7dd3fc !important;
}

.stButton button p,
.stDownloadButton button p {
    color: #ffffff !important;
}

/* Success messages */
div[data-testid="stAlert"] {
    background-color: #172b3a !important;
    border: 1px solid #38bdf8 !important;
    border-radius: 10px !important;
}

div[data-testid="stAlert"] p,
div[data-testid="stAlert"] span {
    color: #ffffff !important;
}

/* Metrics */
[data-testid="stMetric"] {
    background-color: #162235 !important;
    border: 1px solid #263449 !important;
    border-radius: 12px !important;
    padding: 18px !important;
}

[data-testid="stMetricLabel"] {
    color: #cbd5e1 !important;
}

[data-testid="stMetricValue"] {
    color: #38bdf8 !important;
}

[data-testid="stMetricDelta"] {
    color: #4ade80 !important;
}

/* Input fields */
input, textarea {
    background-color: #172235 !important;
    color: #ffffff !important;
    border: 1px solid #334155 !important;
}

/* Dropdowns */
div[data-baseweb="select"] {
    background-color: #172235 !important;
}

div[data-baseweb="select"] * {
    color: #ffffff !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #334155 !important;
    border-radius: 10px !important;
}

/* Expander */
[data-testid="stExpander"] {
    background-color: #142033 !important;
    border: 1px solid #334155 !important;
    border-radius: 10px !important;
}

[data-testid="stExpander"] summary {
    color: #ffffff !important;
}

/* Horizontal line */
hr {
    border-color: #334155 !important;
}

/* Links */
a {
    color: #38bdf8 !important;
}

/* Code blocks */
code {
    color: #7dd3fc !important;
    background-color: #172235 !important;
}

/* Plotly chart background */
.js-plotly-plot {
    background-color: #0b1120 !important;
}

/* Hide default Streamlit footer */
footer {
    visibility: hidden;
}

/* Top header */
header[data-testid="stHeader"] {
    background-color: #0b1120 !important;
}

/* Status widget */
[data-testid="stStatusWidget"] {
    color: #ffffff !important;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def style_chart(fig):
    """Apply dark theme to Plotly charts."""

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b1120",
        plot_bgcolor="#111827",
        font=dict(
            color="#f1f5f9",
            size=13
        ),
        title_font_color="#ffffff",
        legend_font_color="#e2e8f0",
        margin=dict(l=20, r=20, t=50, b=20)
    )

    fig.update_xaxes(
        gridcolor="#263449",
        color="#e2e8f0"
    )

    fig.update_yaxes(
        gridcolor="#263449",
        color="#e2e8f0"
    )

    return fig


def safe_column(df, column, default="Unknown"):
    """Return a column or a default series."""

    if column in df.columns:
        return df[column].fillna(default)

    return pd.Series(
        [default] * len(df),
        index=df.index
    )


def normalize_data(df):
    """Normalize columns used by dashboard."""

    df = df.copy()

    if "anomaly" not in df.columns:
        df["anomaly"] = "Normal"

    if "severity" not in df.columns:
        df["severity"] = "Low"

    if "attack_pattern" not in df.columns:
        df["attack_pattern"] = "Normal Activity"

    if "risk_score" not in df.columns:
        df["risk_score"] = 0

    if "risk_level" not in df.columns:
        df["risk_level"] = "Low"

    if "ip" not in df.columns:
        df["ip"] = "Unknown"

    if "level" not in df.columns:
        df["level"] = "INFO"

    if "status_code" not in df.columns:
        df["status_code"] = 0

    if "endpoint" not in df.columns:
        df["endpoint"] = "Unknown"

    if "response_time" not in df.columns:
        df["response_time"] = 0

    if "timestamp" not in df.columns:
        df["timestamp"] = ""

    return df


def is_anomaly(value):
    """Check anomaly values."""

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return value == 1 or value == -1

    value = str(value).lower()

    return (
        "anomaly" in value
        or "attack" in value
        or value == "-1"
    )


def get_anomaly_dataframe(df):
    return df[df["anomaly"].apply(is_anomaly)].copy()


def create_metric_card(title, value):
    st.metric(
        label=title,
        value=value
    )


# ============================================================
# DATA LOADING
# ============================================================

def load_logs(file_path):

    try:

        result = detect_anomalies(file_path)

        if result is None:
            return None

        if not isinstance(result, pd.DataFrame):
            result = pd.DataFrame(result)

        if result.empty:
            return result

        result = normalize_data(result)

        return result

    except Exception as e:

        st.error(f"Error processing logs: {e}")

        return None


# ============================================================
# PDF REPORT
# ============================================================

def generate_pdf_report(df):

    try:

        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle
        )
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch

        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".pdf"
        )

        temp_file.close()

        doc = SimpleDocTemplate(
            temp_file.name,
            pagesize=A4
        )

        styles = getSampleStyleSheet()

        elements = []

        elements.append(
            Paragraph(
                "<b>LogSentinel AI Security Report</b>",
                styles["Title"]
            )
        )

        elements.append(Spacer(1, 0.3 * inch))

        total = len(df)

        anomalies = len(
            get_anomaly_dataframe(df)
        )

        normal = total - anomalies

        elements.append(
            Paragraph(
                f"Total Logs: {total}",
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"Normal Logs: {normal}",
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"Detected Anomalies: {anomalies}",
                styles["Normal"]
            )
        )

        elements.append(Spacer(1, 0.3 * inch))

        if "attack_pattern" in df.columns:

            patterns = (
                df[df["anomaly"].apply(is_anomaly)]
                ["attack_pattern"]
                .value_counts()
                .head(10)
            )

            table_data = [
                ["Attack Pattern", "Count"]
            ]

            for pattern, count in patterns.items():

                table_data.append([
                    str(pattern),
                    str(count)
                ])

            table = Table(
                table_data,
                colWidths=[4 * inch, 1.5 * inch]
            )

            table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0),
                     colors.HexColor("#0f172a")),

                    ("TEXTCOLOR", (0, 0), (-1, 0),
                     colors.white),

                    ("GRID", (0, 0), (-1, -1),
                     0.5, colors.grey),

                    ("PADDING", (0, 0), (-1, -1), 8)
                ])
            )

            elements.append(table)

        doc.build(elements)

        with open(temp_file.name, "rb") as f:

            pdf_data = f.read()

        os.unlink(temp_file.name)

        return pdf_data

    except Exception as e:

        st.error(f"PDF report error: {e}")

        return None


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <h1 style="color:#38bdf8 !important;">
        🛡️ LogSentinel AI
        </h1>

        <p style="color:#cbd5e1 !important;">
        AI-Powered Log Intelligence
        </p>
        """,
        unsafe_allow_html=True
    )

    st.divider()

    st.subheader("Navigation")

    page = st.radio(
        "Select Page",
        [
            "Overview",
            "Threat Intelligence",
            "Attack Patterns",
            "Log Explorer",
            "About"
        ],
        label_visibility="collapsed"
    )

    st.divider()

    st.markdown(
        """
        <h3 style="color:#38bdf8 !important;">
        📂 Upload Log File
        </h3>
        """,
        unsafe_allow_html=True
    )

    uploaded_file = st.file_uploader(
        "Upload .log or .txt file",
        type=["log", "txt"]
    )

    st.caption(
        "Upload a log file to analyze security threats."
    )

    st.divider()

    st.markdown(
        """
        <p style="color:#94a3b8 !important;">
        LogSentinel AI<br>
        College Project
        </p>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# LOAD DATA
# ============================================================

df = None

if uploaded_file is not None:

    try:

        file_bytes = uploaded_file.getvalue()

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".log"
        ) as temp_file:

            temp_file.write(file_bytes)

            temp_path = temp_file.name

        df = load_logs(temp_path)

        try:
            os.unlink(temp_path)
        except:
            pass

        if df is not None and not df.empty:

            st.sidebar.success(
                f"✅ {len(df)} logs loaded successfully"
            )

    except Exception as e:

        st.sidebar.error(
            f"Upload error: {e}"
        )


else:

    sample_path = os.path.join(
        "data",
        "sample_logs.log"
    )

    if os.path.exists(sample_path):

        df = load_logs(sample_path)

        if df is not None and not df.empty:

            st.sidebar.info(
                "Using sample dataset"
            )

    else:

        st.sidebar.warning(
            "Sample log file not found."
        )


# ============================================================
# EMPTY DATA CHECK
# ============================================================

if df is None or df.empty:

    st.markdown(
        """
        <h1 style="color:#38bdf8 !important;">
        🛡️ LogSentinel AI
        </h1>
        """,
        unsafe_allow_html=True
    )

    st.warning(
        "No logs available. Upload a log file from the sidebar."
    )

    st.stop()


df = normalize_data(df)

anomaly_df = get_anomaly_dataframe(df)

total_logs = len(df)

total_anomalies = len(anomaly_df)

normal_logs = total_logs - total_anomalies


# ============================================================
# OVERVIEW PAGE
# ============================================================

if page == "Overview":

    st.title("🛡️ LogSentinel AI Dashboard")

    st.markdown(
        "AI-powered log analysis and anomaly detection."
    )

    st.divider()

    # Metrics

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Total Logs",
            total_logs
        )

    with col2:

        st.metric(
            "Normal Logs",
            normal_logs
        )

    with col3:

        st.metric(
            "Anomalies Detected",
            total_anomalies
        )

    with col4:

        percentage = (
            round(
                (total_anomalies / total_logs) * 100,
                2
            )
            if total_logs > 0
            else 0
        )

        st.metric(
            "Anomaly Rate",
            f"{percentage}%"
        )

    st.divider()

    # Charts

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Log Classification")

        classification_data = pd.DataFrame({
            "Category": [
                "Normal",
                "Anomaly"
            ],
            "Count": [
                normal_logs,
                total_anomalies
            ]
        })

        fig = px.pie(
            classification_data,
            names="Category",
            values="Count",
            hole=0.5
        )

        fig.update_traces(
            textinfo="label+percent",
            textfont_color="white"
        )

        st.plotly_chart(
            style_chart(fig),
            use_container_width=True
        )

    with col2:

        st.subheader("Severity Distribution")

        severity_counts = (
            df["severity"]
            .astype(str)
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        fig = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            text="Count"
        )

        fig.update_traces(
            textposition="outside"
        )

        st.plotly_chart(
            style_chart(fig),
            use_container_width=True
        )

    # Attack patterns

    st.subheader("Top Attack Patterns")

    attack_data = (
        anomaly_df["attack_pattern"]
        .astype(str)
        .value_counts()
        .head(10)
        .reset_index()
    )

    attack_data.columns = [
        "Attack Pattern",
        "Count"
    ]

    if not attack_data.empty:

        fig = px.bar(
            attack_data,
            x="Count",
            y="Attack Pattern",
            orientation="h",
            text="Count"
        )

        fig.update_traces(
            textposition="outside"
        )

        st.plotly_chart(
            style_chart(fig),
            use_container_width=True
        )

    else:

        st.info(
            "No attack patterns detected."
        )

    # Recent anomalies

    st.subheader("Recent Anomaly Records")

    if not anomaly_df.empty:

        st.dataframe(
            anomaly_df.head(20),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No anomalies detected."
        )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

elif page == "Threat Intelligence":

    st.title("🔎 Threat Intelligence")

    st.markdown(
        """
        IP addresses are ranked using anomaly counts,
        errors and severity indicators.
        Scores are calculated from the uploaded dataset.
        """
    )

    st.divider()

    if "ip" in df.columns:

        ip_data = df.copy()

        ip_data["is_anomaly"] = (
            ip_data["anomaly"].apply(is_anomaly)
        )

        ip_stats = (
            ip_data.groupby("ip")
            .agg(
                Total_Requests=("ip", "count"),
                Anomalies=("is_anomaly", "sum"),
                Average_Risk=("risk_score", "mean")
            )
            .reset_index()
        )

        ip_stats["Average_Risk"] = (
            ip_stats["Average_Risk"]
            .round(2)
        )

        ip_stats = ip_stats.sort_values(
            by=["Anomalies", "Average_Risk"],
            ascending=False
        )

        st.subheader("🌐 IP Risk Analysis")

        st.dataframe(
            ip_stats,
            use_container_width=True,
            hide_index=True
        )

        col1, col2 = st.columns(2)

        with col1:

            st.subheader("Top Risk IPs")

            top_ips = ip_stats.head(10)

            fig = px.bar(
                top_ips,
                x="ip",
                y="Anomalies",
                text="Anomalies"
            )

            fig.update_traces(
                textposition="outside"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        with col2:

            st.subheader("Risk Score Distribution")

            fig = px.histogram(
                ip_stats,
                x="Average_Risk",
                nbins=10
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

    else:

        st.warning(
            "IP address column is not available."
        )


# ============================================================
# ATTACK PATTERNS
# ============================================================

elif page == "Attack Patterns":

    st.title("🚨 Attack Pattern Analysis")

    st.markdown(
        "Detected suspicious activities and attack patterns."
    )

    st.divider()

    if not anomaly_df.empty:

        attack_counts = (
            anomaly_df["attack_pattern"]
            .astype(str)
            .value_counts()
            .reset_index()
        )

        attack_counts.columns = [
            "Attack Pattern",
            "Count"
        ]

        col1, col2 = st.columns(2)

        with col1:

            st.subheader("Attack Pattern Distribution")

            fig = px.bar(
                attack_counts,
                x="Attack Pattern",
                y="Count",
                text="Count"
            )

            fig.update_traces(
                textposition="outside"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        with col2:

            st.subheader("Attack Pattern Breakdown")

            fig = px.pie(
                attack_counts,
                names="Attack Pattern",
                values="Count",
                hole=0.4
            )

            fig.update_traces(
                textinfo="label+percent",
                textfont_color="white"
            )

            st.plotly_chart(
                style_chart(fig),
                use_container_width=True
            )

        st.divider()

        st.subheader("Anomaly Records")

        st.dataframe(
            anomaly_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No anomalies detected in this dataset."
        )


# ============================================================
# LOG EXPLORER
# ============================================================

elif page == "Log Explorer":

    st.title("📋 Log Explorer")

    st.markdown(
        "Search, filter and explore your log records."
    )

    st.divider()

    filtered_df = df.copy()

    col1, col2, col3 = st.columns(3)

    with col1:

        severity_options = sorted(
            df["severity"]
            .astype(str)
            .unique()
            .tolist()
        )

        selected_severity = st.multiselect(
            "Filter by Severity",
            severity_options
        )

    with col2:

        anomaly_options = [
            "All",
            "Normal",
            "Anomaly"
        ]

        selected_anomaly = st.selectbox(
            "Log Type",
            anomaly_options
        )

    with col3:

        search_text = st.text_input(
            "Search Logs",
            placeholder="Search IP, endpoint or keyword..."
        )

    # Severity filter

    if selected_severity:

        filtered_df = filtered_df[
            filtered_df["severity"]
            .astype(str)
            .isin(selected_severity)
        ]

    # Anomaly filter

    if selected_anomaly == "Normal":

        filtered_df = filtered_df[
            ~filtered_df["anomaly"]
            .apply(is_anomaly)
        ]

    elif selected_anomaly == "Anomaly":

        filtered_df = filtered_df[
            filtered_df["anomaly"]
            .apply(is_anomaly)
        ]

    # Text search

    if search_text:

        search_text = search_text.lower()

        mask = filtered_df.astype(str).apply(
            lambda row: row.str.lower()
            .str.contains(
                search_text,
                na=False
            ).any(),
            axis=1
        )

        filtered_df = filtered_df[mask]

    st.divider()

    st.write(
        f"Showing **{len(filtered_df)}** records"
    )

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

    # CSV Export

    csv_data = filtered_df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="📥 Download Filtered Logs CSV",
        data=csv_data,
        file_name="logs_filtered.csv",
        mime="text/csv"
    )


# ============================================================
# ABOUT PAGE
# ============================================================

elif page == "About":

    st.title("ℹ️ About LogSentinel AI")

    st.markdown(
        """
        ## LogSentinel AI

        **AI-Powered Log Intelligence & Anomaly Detection System**

        LogSentinel AI is a Python-based security monitoring
        application designed to analyze server logs and detect
        suspicious activities.

        ### Project Objectives

        - Analyze system and server logs.
        - Detect unusual behavior.
        - Identify suspicious IP addresses.
        - Classify anomalies by severity.
        - Detect common attack patterns.
        - Visualize security insights.
        - Export analysis reports.

        ### Technologies Used

        - Python
        - Streamlit
        - Pandas
        - NumPy
        - Scikit-learn
        - Isolation Forest
        - Plotly
        - ReportLab

        ### Machine Learning

        The project uses Isolation Forest to identify unusual
        log behavior based on selected features.

        ### Main Features

        - Log file upload
        - Anomaly detection
        - Threat intelligence
        - Attack pattern analysis
        - Interactive dashboard
        - Log filtering
        - CSV export
        - PDF report generation

        ### Disclaimer

        This application is an academic project.
        The threat scores are calculated from the provided
        dataset and should not be considered a substitute
        for professional security monitoring.
        """
    )


# ============================================================
# PDF REPORT DOWNLOAD
# ============================================================

st.divider()

st.subheader("📄 Export Security Report")

pdf_data = generate_pdf_report(df)

if pdf_data is not None:

    st.download_button(
        label="📥 Download PDF Security Report",
        data=pdf_data,
        file_name="LogSentinel_AI_Report.pdf",
        mime="application/pdf"
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div style="
        text-align:center;
        padding:20px;
        color:#94a3b8;
        border-top:1px solid #263449;
        margin-top:30px;
    ">
        🛡️ LogSentinel AI |
        AI-Powered Log Intelligence |
        Academic Project
    </div>
    """,
    unsafe_allow_html=True
)