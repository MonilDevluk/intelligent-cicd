# Design Decisions

## Module 1: Webhook Receiver

**Why signature verification?**
GitHub signs every webhook payload with HMAC-SHA256 using a shared secret. Verifying this ensures only GitHub can trigger our pipeline — not anyone who discovers the endpoint URL.

**Why FastAPI over Flask?**
FastAPI handles async requests natively. Webhook payloads need to be read as raw bytes for signature verification before parsing as JSON — FastAPI's Request object supports this cleanly.

**Why a separate router (APIRouter) instead of putting everything in main.py?**
Each module gets its own file. As the pipeline grows, main.py stays clean and just assembles the pieces.

## Module 3: Scanner Engine

**Why Semgrep over Bandit?**
Bandit is Python-only. Semgrep supports multiple languages with the same pipeline — future expansion to JavaScript, Java, etc. requires no changes to the scanner module.

**Why p/python ruleset over --config auto?**
`--config auto` downloads rules at runtime and causes webhook timeouts. `p/python` is a curated, cached ruleset that runs fast enough for a live pipeline.

**Why background tasks instead of inline scanning?**
GitHub webhooks timeout after 10 seconds. Scanning a real repo takes 30-60 seconds. BackgroundTasks lets us respond immediately with 200 and scan asynchronously — the correct pattern for any webhook-triggered pipeline.

## Module 4: AI Patch Generator

**Why Groq over Gemini?**
Gemini free tier has quota restrictions in India (limit: 0). Groq provides genuinely free API access with no regional restrictions. The model (Llama 3.1) is capable enough for code repair tasks.

**Why context-enriched prompting?**
Prior work (Paper 4) used only CWE-ID in the prompt. We send file path, line number, rule ID, severity, message, code snippet, and full file content. This is the core research contribution — we hypothesize this reduces semantic misunderstanding failures.

**Why return the full fixed file instead of just the changed lines?**
Patch application is simpler and safer with a full file replacement. Diff-based patching requires line-level alignment which breaks easily on reformatted code.
