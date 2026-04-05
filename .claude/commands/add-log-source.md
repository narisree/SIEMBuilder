# /add-log-source

You are helping the user add a new log source to SIEMBuilder.

## Steps

1. **Ask** the user for the log source name and slug (e.g., name: "Palo Alto Firewall", slug: "palo-alto-firewall")

2. **Update `kb/sources_catalog.json`** — add a new entry following the existing format:
   ```json
   {
     "id": "<slug>",
     "name": "<Display Name>",
     "vendor": "<Vendor>",
     "category": "<e.g. Network, Endpoint, Cloud>",
     "description": "<short description>"
   }
   ```

3. **Create `kb/<slug>.md`** — integration guide following the structure of an existing guide. Include:
   - Overview
   - Prerequisites
   - Integration steps
   - Field mappings (CIM model)
   - Sample SPL queries
   - Common issues

4. **Update `kb/references.json`** — add documentation and video links for this log source

5. **Update `app.py` `SOURCE_DISPLAY_NAMES`** dict with the new slug → display name mapping

6. **Verify** by running `streamlit run app.py` and checking the new source appears in the dropdown

Always ask the user for any vendor-specific details you need. Do not guess log formats.
