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

## Module 5: Sandbox Tester

**Why Bandit as a second static analysis layer instead of trusting the LLM patch directly?**
The LLM can produce a patch that looks correct but introduces a new issue, or doesn't fully resolve the original one. Bandit re-scans the patched code independently, so the pipeline never ships a fix on the model's word alone — every patch passes through an automated reviewer before it reaches a PR.

**Why auto-generate a pytest file per patch instead of reusing one fixed test template?**
Each vulnerability is shaped differently — a SQLi fix and a command-injection fix need different assertions to prove the fix actually works. Asking the LLM to generate a test alongside the patch keeps the validation specific to that exact finding, rather than a generic "does it still run" check.

**Why classify sandbox results into SAFE / NEEDS_REVIEW / UNVERIFIED instead of a binary pass/fail?**
A binary flag hides important nuance. NEEDS_REVIEW means the patch ran but something about the test or Bandit output deserves a human look before merging — that distinction matters for an autonomous system that's allowed to open real PRs.

## Module 6: Database Layer (Supabase)

**Why Supabase over a local SQLite file?**
The dashboard, the webhook server, and any future analysis script all need to read the same data without file-locking issues. Supabase gives a hosted Postgres instance with a REST API out of the box, so the dashboard can query it directly without going through the backend for every read.

**Why store `prompt_condition` as a column instead of running two separate tables for minimal vs enriched?**
The research question is a within-finding comparison — for the *same* vulnerability, did minimal or enriched produce the better patch? Keeping both conditions as rows in one table with a `prompt_condition` flag makes that comparison a single query instead of a join across tables.

**Why store both `original_code` and `code_snippet` (on findings) separately, instead of relying on one?**
We learned this one the hard way — see the documented bug below. Storing `original_code` directly inside the `patches` table, captured at the moment the patch was generated, became the reliable source of truth when the scanner-level `code_snippet` field turned out to be unreliable for one specific rule.

## Module 7: PR Creator

**Why create a real GitHub PR instead of just storing the patch in the database?**
A patch sitting in a database is invisible to the actual workflow a developer uses. Opening a PR puts the fix exactly where a reviewer already looks — it turns "the system found something" into "here's a mergeable fix," which is the difference between a research demo and something that could plug into a real team's process.

**Why append a Unix timestamp to the branch name?**
Branch names were originally built from the condition, rule, and line number only (`autofix/minimal-subprocess-shell-true-L3`). The same finding pushed twice — which happens constantly during testing and demos — produced the same branch name, GitHub silently rejected the second `git/refs` call, and `pr_url` came back as `None` even though the patch itself was fine. Appending `int(time.time())` guarantees a unique branch per pipeline run.

## Module 8: React Dashboard

**Why a single-page dashboard instead of separate pages per scan?**
Mentor demos and research review both benefit from being able to compare multiple scans side by side without losing context. The tabbed interface (each clicked scan opens as its own closeable tab) keeps several findings on screen at once without re-fetching or re-navigating.

**Why a light/dark toggle instead of picking one theme permanently?**
Demo environments vary — a projector in a bright room reads better in light mode, a personal screen at night is easier in dark mode. Since the underlying data and layout don't change, theming was cheap to add as a toggle rather than a one-time decision.

## Cross-cutting: Concurrency and Reliability

**Why a global in-memory lock flag instead of a database-backed lock or a queue?**
GitHub redelivers the same webhook event multiple times within seconds if the response is slow, which was creating 3-4 concurrent pipeline runs per single push and exhausting the Groq rate limit. A single process-level boolean (`_pipeline_running`) was the simplest fix that matched the actual failure mode — this system runs as one process during development and demos, so a database-backed lock would have been solving a problem we don't have yet.

**Why replace `print()` with a central `logger` everywhere, including in `patcher.py`'s retry path?**
Print statements don't carry severity or timestamps and get lost in a long-running server's stdout. The central logger (`logger.py`) was introduced early for the main pipeline flow, but `patcher.py`'s Groq retry/backoff logic still used `print()` until we caught the inconsistency — every error and retry should be traceable in the same log stream, especially during a live demo where something might fail mid-run.

## Documented Bug: The "requires login" Phantom Snippet

**What happened:** Multiple findings across different scans — different files, different vulnerability types — all showed the exact same `code_snippet` value: `"requires login"`. None of the actual scanned files contained that string anywhere.

**Investigation:** Traced through `scanner.py` (correctly extracts `r["extra"]["lines"]` from Semgrep's JSON output), `webhook.py` (correctly passes the finding dict through unmodified), and `database.py` (correctly inserts the value as given) — no bug found in our own code. Reproduced independently by running `semgrep --config p/python` directly against a clean, minimal vulnerable file containing only the `subprocess` + `shell=True` pattern. Semgrep's own JSON output returned `"requires login"` as the `lines` value for that match.

**Root cause:** This is a quirk in Semgrep's `p/python` ruleset itself — specifically the `subprocess-shell-true` rule — where the `lines` field in the JSON output does not reliably reflect the actual matched source line for every rule. It appears to return an unrelated string from the rule's own metadata or message template in certain cases, rather than the source code at the match location.

**Why this matters for the research:** It's a clean example of why we don't fully trust scanner output for anything beyond *triggering* the pipeline. The `original_code` field on the `patches` table — captured directly from the file content at patch-generation time, not from Semgrep's `lines` field — became the dependable source of truth for what the vulnerable code actually looked like. The dashboard's "Vulnerable Code" display (sourced from `findings.code_snippet`) can be unreliable for this specific rule; the "Original Code" shown alongside each patch is not.

**Fix applied:** None needed in our code — this is a known limitation of relying on `code_snippet` from Semgrep for display purposes. Documented here so it isn't mistaken for our own scanner bug if it resurfaces, and as a deliberate design justification for why `patches.original_code` exists as a separate, independently-captured field rather than a redundant copy of `findings.code_snippet`.

## Follow-up: Fixing the Same Bug at the PR Level

The dashboard fix (falling back to `patch.original_code`) only addressed the React frontend. The GitHub PR description itself is generated server-side in `github_pr.py`, which was still building its "Vulnerable Code" section directly from `finding['code_snippet']` — the same unreliable field. The PR is the artifact a reviewer actually reads, so this needed its own fix rather than relying on the dashboard's client-side correction.

**Fix:** `create_pull_request()` now accepts an optional `original_content` parameter. `webhook.py` already has the real file content in scope at the point it calls `create_pull_request` (it's read directly from disk before any LLM call), so passing it straight through closes the gap with no new file reads or scanner calls. The PR body now prefers `original_content` and only falls back to `finding['code_snippet']` if it's missing, keeping backward compatibility with any code path that doesn't supply it.

## Documented Bug: PR URL Returning None on Repeated Pushes

**What happened:** When the same finding triggered a patch more than once — which happens constantly while testing, since the same vulnerable file gets pushed repeatedly during development — the resulting `pr_url` came back as `None` and no PR appeared on GitHub, even though the scan, patch generation, and sandbox validation all completed successfully.

**Investigation:** The branch name passed to GitHub's `git/refs` API was built only from the prompt condition, the rule's short name, and the line number (`autofix/minimal-subprocess-shell-true-L3`). None of those values change between two pushes of the same vulnerable file, so the second run tried to create a branch that already existed from the first run. GitHub's API rejected the duplicate ref creation, the PR step failed silently inside a try/except, and the pipeline continued on to save the patch with an empty `pr_url`.

**Root cause:** Branch naming had no uniqueness guarantee across pipeline runs — it only guaranteed uniqueness across different findings within a single run, not across repeated runs of the same finding.

**Fix:** Appended `int(time.time())` to the branch name, so every pipeline run gets a branch unique to that exact execution, regardless of how many times the same vulnerability gets re-triggered.

## Documented Bug: Concurrent Pipeline Execution from Rapid Pushes

**What happened:** A single `git push` was triggering 3-4 separate pipeline runs back to back, each one independently calling Semgrep, Groq, Bandit, and the PR creation step for the same commit. This burned through the Groq daily rate limit far faster than expected and produced duplicate PRs for the same finding.

**Investigation:** GitHub redelivers a webhook event if it doesn't receive a response quickly enough, and our endpoint was already taking long enough (queuing a background task, but still doing some synchronous work before returning) that GitHub occasionally sent the same push event two or three times within seconds. Each delivery passed signature verification (since it really was the same legitimate event from GitHub) and was treated as a brand new pipeline run.

**Root cause:** The webhook handler had no concept of "a pipeline is already running" — every valid signed request was assumed to be a new job, with no deduplication against in-flight work.

**Fix:** Added a single process-level boolean flag (`_pipeline_running`) checked both at the webhook endpoint (to reject redundant deliveries immediately) and inside `process_repo` itself (as a safety net in case two background tasks somehow both got scheduled). The flag is set the moment a pipeline starts and released in the `finally` block, so it clears even if the pipeline fails partway through.

## Documented Issue: Dashboard Losing Scroll Position on Scan Selection

**What happened:** Clicking a different scan in the sidebar updated the findings panel correctly, but the page stayed scrolled to wherever the user had been browsing previously — meaning the newly loaded findings were often off-screen below the fold, requiring a manual scroll up to actually see them.

**Root cause:** `loadScan()` updated state but never reset the viewport position, since the original single-page layout had no reason to assume the user would be scrolled away from the top when switching scans.

**Fix:** Initially added an instant `window.scrollTo(0, 0)` on every scan load. This was superseded shortly after by a layout-level fix — the header and stats bar were made fixed, and the scan list and findings panel were each given their own independent internal scroll containers — which made the scroll-reset unnecessary, since switching scans no longer affects the page's overall scroll position at all.
