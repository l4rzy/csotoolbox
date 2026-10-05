import sys

import infrastructure.constants as _constants

if "--prod" in sys.argv:
    _constants.VERSION_REVISION = "PROD"

from app import app
import uvicorn
import os


if __name__ == "__main__":
    cert_path = "data/cert.pem"
    key_path = "data/key.pem"
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print("Starting HTTPS server on port 5059...")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=5059,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path,
        )
    else:
        print("No SSL certificate/key found. HTTPS-only: place cert.pem and key.pem in data/")
        sys.exit(1)
