import uvicorn
import os
import sys

# Ensure backend root is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

port = int(os.getenv("PORT", "8001"))
host = os.getenv("HOST", "0.0.0.0" if os.getenv("ENVIRONMENT") == "production" else "127.0.0.1")

if __name__ == "__main__":
    print(f"[*] Starting DNS Shield AI FastAPI Backend on http://{host}:{port} ...")
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
