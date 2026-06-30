import os

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
URLHAUS_BASE_URL = os.getenv("URLHAUS_BASE_URL", "https://urlhaus-api.abuse.ch/v1")
URLHAUS_TIMEOUT_SECONDS = int(os.getenv("URLHAUS_TIMEOUT_SECONDS", "20"))
URLHAUS_ENABLE_SUBMISSION = os.getenv("URLHAUS_ENABLE_SUBMISSION", "false").lower() == "true"
URLHAUS_ENABLE_MALWARE_DOWNLOAD = os.getenv("URLHAUS_ENABLE_MALWARE_DOWNLOAD", "false").lower() == "true"
