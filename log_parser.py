import pandas as pd
from pathlib import Path


def parse_logs(file_path):
    """
    Parse structured log files into a Pandas DataFrame.

    Expected format:
    YYYY-MM-DD HH:MM:SS LEVEL IP METHOD ENDPOINT STATUS RESPONSE_TIME
    """

    log_data = []

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with open(path, "r", encoding="utf-8", errors="replace") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 8:
                continue

            try:

                entry = {
                    "date": parts[0],
                    "time": parts[1],
                    "level": parts[2].upper(),
                    "ip": parts[3],
                    "method": parts[4].upper(),
                    "endpoint": parts[5],
                    "status_code": int(parts[6]),
                    "response_time": int(
                        parts[7].lower().replace("ms", "")
                    )
                }

                log_data.append(entry)

            except (ValueError, IndexError):
                continue

    columns = [
        "date",
        "time",
        "level",
        "ip",
        "method",
        "endpoint",
        "status_code",
        "response_time"
    ]

    df = pd.DataFrame(log_data, columns=columns)

    if not df.empty:

        df["timestamp"] = pd.to_datetime(
            df["date"] + " " + df["time"],
            errors="coerce"
        )

        df = df.dropna(subset=["timestamp"])

        df = df.reset_index(drop=True)

    return df


if __name__ == "__main__":

    file_path = "data/sample_logs.log"

    df = parse_logs(file_path)

    print("\n========== LOG PARSER RESULTS ==========")

    print("Total Logs Parsed:", len(df))

    print("\nFirst 10 Records:")

    print(df.head(10))

    print("\nLog Levels:")

    print(df["level"].value_counts())

    print("\nStatus Codes:")

    print(df["status_code"].value_counts())

    print("\nData Information:")

    print(df.info())