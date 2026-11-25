import random
from datetime import datetime, timedelta
from pathlib import Path


# ==========================================
# CONFIGURATION
# ==========================================

TOTAL_LOGS = 1000
SUSPICIOUS_LOGS = 100

random.seed(42)


# ==========================================
# IP ADDRESSES
# ==========================================

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.8"
]

SUSPICIOUS_IPS = [
    "185.220.101.45",
    "45.155.205.233",
    "103.77.192.12"
]


# ==========================================
# ENDPOINTS
# ==========================================

NORMAL_ENDPOINTS = [
    "/home",
    "/login",
    "/dashboard",
    "/profile",
    "/products",
    "/about",
    "/contact",
    "/services"
]

SUSPICIOUS_ENDPOINTS = [
    "/admin",
    "/wp-admin",
    "/etc/passwd",
    "/phpmyadmin",
    "/.env",
    "/config",
    "/backup",
    "/api/keys"
]


# ==========================================
# GENERATE LOG DATA
# ==========================================

def generate_logs():

    Path("data").mkdir(
        parents=True,
        exist_ok=True
    )

    logs = []

    start_time = datetime.now() - timedelta(days=1)

    for i in range(TOTAL_LOGS):

        suspicious = i < SUSPICIOUS_LOGS

        # IP selection

        if suspicious:

            ip = random.choice(SUSPICIOUS_IPS)

        else:

            ip = random.choice(NORMAL_IPS)

        # Endpoint selection

        if suspicious:

            endpoint = random.choice(
                SUSPICIOUS_ENDPOINTS
            )

        else:

            endpoint = random.choice(
                NORMAL_ENDPOINTS
            )

        # HTTP method

        method = random.choice([
            "GET",
            "POST"
        ])

        # Status code

        if suspicious:

            status_code = random.choice([
                401,
                403,
                404,
                429,
                500,
                503
            ])

            level = random.choice([
                "WARNING",
                "ERROR"
            ])

            response_time = random.randint(
                500,
                3500
            )

        else:

            status_code = random.choice([
                200,
                200,
                200,
                201,
                204
            ])

            level = "INFO"

            response_time = random.randint(
                30,
                450
            )

        # Timestamp

        timestamp = start_time + timedelta(
            seconds=random.randint(
                0,
                86400
            )
        )

        date = timestamp.strftime(
            "%Y-%m-%d"
        )

        time = timestamp.strftime(
            "%H:%M:%S"
        )

        # Create log line

        log_line = (
            f"{date} "
            f"{time} "
            f"{level} "
            f"{ip} "
            f"{method} "
            f"{endpoint} "
            f"{status_code} "
            f"{response_time}ms"
        )

        logs.append(log_line)

    # Shuffle records

    random.shuffle(logs)

    # Save dataset

    file_path = Path(
        "data/sample_logs.log"
    )

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "\n".join(logs)
        )

        file.write("\n")

    # ======================================
    # SUMMARY
    # ======================================

    print("\n===================================")

    print(" LOGSENTINEL AI - DATA GENERATOR")

    print("===================================")

    print("Total Logs Generated:", TOTAL_LOGS)

    print("Normal Logs:", TOTAL_LOGS - SUSPICIOUS_LOGS)

    print("Suspicious Logs:", SUSPICIOUS_LOGS)

    print("Dataset Location:", file_path)

    print("\nDataset Generated Successfully!")

    print("===================================")


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    generate_logs()