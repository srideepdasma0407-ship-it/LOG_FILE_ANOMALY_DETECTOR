import pandas as pd
from sklearn.ensemble import IsolationForest
from log_parser import parse_logs


# ==========================================
# SUSPICIOUS ENDPOINTS
# ==========================================

SUSPICIOUS_ENDPOINTS = [
    "/admin",
    "/wp-admin",
    "/etc/passwd",
    "/phpmyadmin",
    "/.env",
    "/config",
    "/backup",
    "/api/keys",
    "/server-status"
]


# ==========================================
# AI ANOMALY DETECTION
# ==========================================

def detect_anomalies(file_path):

    df = parse_logs(file_path)

    if df.empty:
        return df

    # ======================================
    # FEATURE ENGINEERING
    # ======================================

    df["is_error"] = df["level"].isin(
        ["ERROR", "WARNING"]
    ).astype(int)

    df["is_suspicious_endpoint"] = df["endpoint"].apply(
        lambda endpoint: int(
            any(
                suspicious in str(endpoint).lower()
                for suspicious in SUSPICIOUS_ENDPOINTS
            )
        )
    )

    df["ip_frequency"] = df.groupby("ip")["ip"].transform("count")

    df["failed_request"] = df["status_code"].isin(
        [401, 403, 404, 429]
    ).astype(int)

    df["server_error"] = (
        df["status_code"] >= 500
    ).astype(int)

    # ======================================
    # MACHINE LEARNING FEATURES
    # ======================================

    features = [
        "status_code",
        "response_time",
        "is_error",
        "is_suspicious_endpoint",
        "ip_frequency",
        "failed_request",
        "server_error"
    ]

    # ======================================
    # ISOLATION FOREST MODEL
    # ======================================

    model = IsolationForest(
        n_estimators=150,
        contamination=0.08,
        random_state=42
    )

    predictions = model.fit_predict(df[features])

    df["anomaly"] = [
        "Anomaly" if prediction == -1 else "Normal"
        for prediction in predictions
    ]

    # ======================================
    # SEVERITY CLASSIFICATION
    # ======================================

    df["severity"] = "Low"

    df.loc[
        df["anomaly"] == "Anomaly",
        "severity"
    ] = "Medium"

    high_risk_condition = (
        df["is_suspicious_endpoint"].eq(1)
        | df["status_code"].ge(500)
        | df["status_code"].eq(429)
    )

    df.loc[
        high_risk_condition,
        "severity"
    ] = "High"

    # ======================================
    # ATTACK PATTERN CLASSIFICATION
    # ======================================

    df["attack_pattern"] = "Unusual Activity"

    df.loc[
        df["is_suspicious_endpoint"] == 1,
        "attack_pattern"
    ] = "Suspicious Endpoint Access"

    df.loc[
        df["status_code"] == 429,
        "attack_pattern"
    ] = "Rate Limit / Possible Flood"

    df.loc[
        df["status_code"].isin([401, 403]),
        "attack_pattern"
    ] = "Authentication / Access Failure"

    df.loc[
        df["status_code"] == 404,
        "attack_pattern"
    ] = "Endpoint Probing"

    df.loc[
        df["status_code"] >= 500,
        "attack_pattern"
    ] = "Server Error"

    df.loc[
        df["response_time"] >= 2000,
        "attack_pattern"
    ] = "Slow Response / Possible DoS Indicator"

    # ======================================
    # IP INTELLIGENCE
    # ======================================

    ip_stats = df.groupby("ip").agg(

        requests=("ip", "count"),

        failures=("failed_request", "sum"),

        suspicious_endpoints=(
            "is_suspicious_endpoint",
            "sum"
        ),

        anomalies=(
            "anomaly",
            lambda values: (values == "Anomaly").sum()
        ),

        avg_response_ms=(
            "response_time",
            "mean"
        ),

        server_errors=(
            "server_error",
            "sum"
        )

    ).reset_index()

    # ======================================
    # IP INTELLIGENCE LABEL
    # ======================================

    ip_stats["intel"] = "Normal Traffic"

    ip_stats.loc[
        ip_stats["requests"] >= 50,
        "intel"
    ] = "High Request Volume"

    ip_stats.loc[
        ip_stats["failures"] >= 10,
        "intel"
    ] = "Repeated Failed Requests"

    ip_stats.loc[
        ip_stats["suspicious_endpoints"] >= 1,
        "intel"
    ] = "Suspicious Endpoint Access"

    ip_stats.loc[
        ip_stats["server_errors"] >= 5,
        "intel"
    ] = "Repeated Server Errors"

    # ======================================
    # RISK SCORE
    # ======================================

    risk_score = (

        ip_stats["requests"] * 0.15

        + ip_stats["failures"] * 2

        + ip_stats["suspicious_endpoints"] * 12

        + ip_stats["server_errors"] * 3

        + ip_stats["anomalies"] * 1.5

    )

    ip_stats["risk_score"] = (
        risk_score.clip(0, 100).round(1)
    )

    # ======================================
    # RISK LEVEL
    # ======================================

    ip_stats["risk_level"] = pd.cut(

        ip_stats["risk_score"],

        bins=[-1, 25, 60, 100],

        labels=["Low", "Medium", "High"]

    ).astype(str)

    # ======================================
    # MERGE IP INTELLIGENCE WITH LOGS
    # ======================================

    df = df.merge(

        ip_stats[
            [
                "ip",
                "risk_score",
                "risk_level",
                "intel"
            ]
        ],

        on="ip",

        how="left"

    )

    # ======================================
    # RETURN FINAL DATASET
    # ======================================

    return df


# ==========================================
# TESTING
# ==========================================

if __name__ == "__main__":

    file_path = "data/sample_logs.log"

    df = detect_anomalies(file_path)

    print("\n========== LOGSENTINEL AI ==========")

    print("Total Logs:", len(df))

    print(
        "Normal Logs:",
        (df["anomaly"] == "Normal").sum()
    )

    print(
        "Anomalies:",
        (df["anomaly"] == "Anomaly").sum()
    )

    print("\n========== SEVERITY REPORT ==========")

    print(df["severity"].value_counts())

    print("\n========== ATTACK PATTERNS ==========")

    print(df["attack_pattern"].value_counts())

    print("\n========== IP INTELLIGENCE ==========")

    ip_report = df.groupby("ip").agg(

        Requests=("ip", "count"),

        Anomalies=(
            "anomaly",
            lambda values: (values == "Anomaly").sum()
        ),

        Risk_Score=("risk_score", "max"),

        Risk_Level=("risk_level", "first"),

        Intelligence=("intel", "first")

    ).reset_index()

    print(
        ip_report.sort_values(
            "Risk_Score",
            ascending=False
        )
    )

    print("\n========== ANOMALY PREVIEW ==========")

    print(
        df[df["anomaly"] == "Anomaly"][
            [
                "ip",
                "endpoint",
                "status_code",
                "response_time",
                "severity",
                "attack_pattern",
                "risk_score"
            ]
        ].head(10)
    )