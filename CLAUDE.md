# CLAUDE.md

This file provides guidance to Claude Code when working with the SIEMBuilder repository.
Keep this file under 200 lines for reliable adherence.

## Quick Start

```bash
# Run the application
streamlit run app.py
# Opens at http://localhost:8501

# Install dependencies
pip install -r requirements.txt
```

## Architecture

### Entry Point
`app.py` is the sole Streamlit entry point with three views:
- **Dashboard** – coverage metrics across all 21 log sources
- **Log Source Onboarding** – 5-tab view: Integration Guide, References, Chat, Use Cases, Response Plans
- **Incident Response Playbooks** – 5 IRPs with Mermaid flowcharts

### Core Data Flow
1. User selects a log source → `KBLoader` loads markdown guide + references + catalog metadata
2. Chat input → `AIClientFactory` picks a configured provider → context-aware response
3. Use cases tab → `UseCaseLoader` (CSV) + `SplunkPublicUseCaseLoader` (Excel) → deduplicated display with L1 enrichment
4. Response plan generation → `ResponsePlanGenerator` builds prompt → AI generates runbook → cached to `response_plans/`
5. Escalation path → `IRPLoader` maps MITRE tactic → relevant IRP playbook

### Key Modules (`utils/`)
| File | Responsibility |
|------|---------------|
| `ai_client.py` | Multi-backend AI via `BaseAIClient` → `ClaudeClient`, `GroqClient`, `HuggingFaceClient`, `OllamaClient`; `AIClientFactory` selects based on available secrets |
| `kb_loader.py` | Loads `kb/*.md` guides, `kb/references.json`, `kb/sources_catalog.json` (21 sources) |
| `usecase_loader.py` | Parses `kb/library.csv`; adds L1 guidance keyed on MITRE tactic |
| `splunk_public_usecase_loader.py` | Parses `kb/Splunk_Library_batch_final.xlsx` (500+ detections); matches via `Normalized_Sources` column |
| `irp_loader.py` | Loads `Playbooks/*.md`; maps MITRE tactics → relevant IRPs for escalation |
| `response_plan_generator.py` | Builds system/user prompts; generates and disk-caches response runbooks |
| `mermaid_renderer.py` | Injects Mermaid JS for flowcharts in IRP playbooks |

### Data Sources (`kb/`)
- `*.md` – Integration guides per log source (one file per source slug)
- `library.csv` – Internal use cases with SPL queries
- `Splunk_Library_batch_final.xlsx` – Splunk public use cases
- `sources_catalog.json` – Metadata for all 21 log sources
- `references.json` – Curated docs/video links per source

### AI Provider Priority
`AIClientFactory` checks secrets in order: Groq → HuggingFace → Claude → Ollama (local).

### Caching
Generated response plans are written to `response_plans/<source>_<use_case_hash>.md` and loaded on subsequent visits.

## Adding a New Log Source
1. Add entry to `kb/sources_catalog.json`
2. Create `kb/<source-slug>.md` integration guide
3. Add references to `kb/references.json`
4. Add display name mapping in `app.py` (`SOURCE_DISPLAY_NAMES`)

## AI Provider Config
Create `.streamlit/secrets.toml`:
```toml
GROQ_API_KEY = "gsk_..."          # Free, recommended
ANTHROPIC_API_KEY = "sk-ant-..."  # Paid
HUGGINGFACE_API_KEY = "hf_..."    # Free
# Ollama: no key needed, runs locally
```

## Coding Rules

- **Always start complex tasks in plan mode** — think before coding
- **Commit often** — one logical change per commit, descriptive message
- **Keep `app.py` clean** — delegate logic to `utils/` modules, never put business logic directly in app.py
- **Never break existing AI provider fallback chain** — always test all providers still work
- **Streamlit state** — use `st.session_state` for all persistent UI state
- **Run `streamlit run app.py`** to verify changes before declaring done
- **Use subagents** for parallel tasks — say "use subagents" to parallelize research/implementation

## Debugging Tips
- Use `/doctor` for Claude Code diagnostics
- Take screenshots and share when stuck on UI issues
- Run Streamlit as a background task for log visibility
- Use `/compact` at ~50% context usage to avoid degraded performance
