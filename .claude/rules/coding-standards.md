# Python / Streamlit Coding Standards for SIEMBuilder

## File Organization
- All business logic lives in `utils/` — never in `app.py` directly
- `app.py` only handles: UI layout, routing between views, calling utils functions
- Each util module has a single responsibility (see CLAUDE.md for the list)

## Streamlit Patterns
- Use `st.session_state` for all state that persists across reruns
- Initialize session state at the top of the function: `if "key" not in st.session_state: st.session_state.key = default`
- Use `@st.cache_data` for expensive data loads (CSV, Excel, JSON files)
- Use `@st.cache_resource` for connection objects (AI clients)
- Never use `st.experimental_*` — use stable APIs only

## AI Client Pattern
- Always use `AIClientFactory.create()` — never instantiate clients directly
- Never hardcode model names in app.py — they belong in the client classes
- Always handle `Exception` from AI calls gracefully with a user-friendly error message
- The fallback chain (Groq → HuggingFace → Claude → Ollama) must never be broken

## Data Files
- `kb/sources_catalog.json` and `kb/references.json` are source-of-truth — keep them valid JSON always
- Never write to `kb/*.md` files programmatically without user confirmation
- `response_plans/` is auto-generated cache — safe to delete and regenerate

## Error Handling
- Always wrap AI calls in try/except
- Show errors with `st.error()` not `print()` or bare `raise`
- Log errors but never expose API keys or secrets in error messages

## Code Style
- Follow PEP 8
- Docstrings on all public functions
- Type hints on function signatures where practical
- Keep functions under 50 lines — extract helpers if they grow larger
