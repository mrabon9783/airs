import time
import requests
import os

API_URL = os.getenv("AIRS_API_URL", "http://api:8000")
INTERVAL_SECONDS = int(os.getenv("AIRS_SCAN_INTERVAL_SECONDS", "3600"))


def main() -> None:
    while True:
        try:
            requests.post(f"{API_URL}/scan/run", timeout=600)
        except Exception as exc:
            print(f"scan trigger failed: {exc}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
