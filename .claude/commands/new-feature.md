# /new-feature

You are helping the user implement a new feature in SIEMBuilder using best practices.

## Workflow: Research → Plan → Execute → Verify

### Step 1: Research
- Read `CLAUDE.md` fully to understand the architecture
- Read relevant files in `utils/` and `app.py` to understand current patterns
- Identify which modules will be affected
- Do NOT write any code yet

### Step 2: Plan
- Write a clear implementation plan with:
  - What files will change and why
  - What new files will be created (if any)
  - Potential risks or breaking changes
  - How you'll verify success
- Present the plan to the user and ask for approval before proceeding

### Step 3: Execute
- Implement changes following existing code patterns
- Keep `app.py` clean — move any business logic to `utils/`
- Use `st.session_state` for Streamlit UI state
- Add comments for non-obvious logic

### Step 4: Verify
- Run `streamlit run app.py` to confirm the app starts without errors
- Manually verify the new feature works as expected
- Check that existing features (Dashboard, Chat, Use Cases, Response Plans) still work
- Report results to the user

Always maintain the AI provider fallback chain: Groq → HuggingFace → Claude → Ollama.
