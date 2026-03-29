# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Run the application
```bash
streamlit run app.py
```
Opens at http://localhost:8501

### Install dependencies
```bash
pip install -r requirements.txt
```

### Configure AI provider (required)
Create `.streamlit/secrets.toml` with one of:
```toml
GROQ_API_KEY = "gsk_..."          # Free, recommended
ANTHROPIC_API_KEY = "sk-ant-..."  # Paid
HUGGINGFACE_API_KEY = "hf_..."    # Free
# Ollama: no key needed, runs locally
```

## Architecture

### Entry Point
`app.py` is the sole Streamlit entry point with three views:
- **Dashboard** – coverage metrics across all log sources
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
- `Playbooks/IRP-*.md` – 5 incident response playbooks

### Adding a New Log Source
1. Add entry to `kb/sources_catalog.json`
2. Create `kb/<source-slug>.md` integration guide
3. Add references to `kb/references.json`
4. Add display name mapping in `app.py` (`SOURCE_DISPLAY_NAMES`)

### AI Provider Priority
`AIClientFactory` checks secrets in this order: Groq → HuggingFace → Claude → Ollama (local).

### Caching
Generated response plans are written to `response_plans/<source>_<use_case_hash>.md` and loaded on subsequent visits to avoid redundant API calls.
