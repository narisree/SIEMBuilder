# /health-check

Run a full health check on the SIEMBuilder codebase.

## Checks to Perform

### 1. Structure Check
- Verify all expected `utils/` modules exist: `ai_client.py`, `kb_loader.py`, `usecase_loader.py`, `splunk_public_usecase_loader.py`, `irp_loader.py`, `response_plan_generator.py`, `mermaid_renderer.py`
- Verify `kb/sources_catalog.json` exists and is valid JSON
- Verify `kb/references.json` exists and is valid JSON
- Verify `kb/library.csv` exists
- Verify at least one `kb/*.md` integration guide exists
- Verify at least one `Playbooks/IRP-*.md` exists

### 2. Consistency Check
- Cross-check: every source in `sources_catalog.json` should have a matching `kb/<slug>.md`
- Cross-check: every source slug in `app.py SOURCE_DISPLAY_NAMES` should exist in `sources_catalog.json`
- List any orphaned files (kb/*.md with no matching catalog entry)

### 3. Code Quality Check
- Check `app.py` for any business logic that should be in `utils/`
- Check for any hardcoded API keys or secrets
- Check that `st.session_state` is used properly for UI state

### 4. Dependency Check
- Read `requirements.txt` and verify all imports in `app.py` and `utils/*.py` are listed

## Report Format
Produce a markdown health report with:
- ✅ Passed checks
- ⚠️ Warnings (non-breaking issues)
- ❌ Failed checks (broken things that need fixing)
- 📋 Recommended actions
