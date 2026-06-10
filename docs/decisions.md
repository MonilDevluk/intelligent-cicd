# Design Decisions

## Module 1: Webhook Receiver

**Why signature verification?**
GitHub signs every webhook payload with HMAC-SHA256 using a shared secret. Verifying this ensures only GitHub can trigger our pipeline — not anyone who discovers the endpoint URL.

**Why FastAPI over Flask?**
FastAPI handles async requests natively. Webhook payloads need to be read as raw bytes for signature verification before parsing as JSON — FastAPI's Request object supports this cleanly.

**Why a separate router (APIRouter) instead of putting everything in main.py?**
Each module gets its own file. As the pipeline grows, main.py stays clean and just assembles the pieces.
