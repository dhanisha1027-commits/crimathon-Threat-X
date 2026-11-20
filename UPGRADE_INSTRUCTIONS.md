# ThreatX NEEDZERO — Manual Access Manager Upgrade

This upgrade adds a backend-enforced Read/Write permission editor and a one-time-token rotation button. It uses **the same SQLite schema** as the original prototype. Your existing local database can be kept.

## How to update your existing Windows project safely

1. **Stop** `python app.py` with `Ctrl+C`.
2. Back up the entire existing `ThreatX_NEEDZERO` folder, especially `data/threatx.sqlite` and `.demo-credentials.txt`.
3. Copy the updated **app.py**, **core.py**, **static/admin.html**, **static/main.js**, **static/styles.css**, and **tests/test_core.py** files from this ZIP into your existing project (replace the code files only).
4. Do **not** replace or delete `data/` or `.demo-credentials.txt`. Those files are not packaged in this ZIP.
5. Run `python -m unittest discover -s tests -v`, then `python app.py`.
6. Refresh Chrome with `Ctrl+F5`. Go to the **Access Contract** section. You should see a new Manual Read / Write Permissions table and a button to Issue Replacement API Token.
7. If your original TallyBridge token was revoked, click **Issue Replacement API Token**. Copy the new token; it is displayed once and entered automatically into your API Playground. The previous token will immediately fail.
8. Tick/untick fields and click **Save Manual Permissions**. Test from the **Live API Playground** to see the actual HTTP authorization results. `WRITE: 0 fields` means all third-party changes are denied.

## Notes
- The Permission Necessity Lab is unchanged; you can choose automatic results or save your own manual fields.
- If you click **Apply Experiment-Based Contract**, it overwrites manual fields with the experiment recommendation. Use **Save Manual Permissions** afterward if you want custom fields.
- Sensitive financial-field writes require an explicit high-risk acknowledgement; this is only a simulated research demonstration.
- Existing audit records remain in the SQLite database.
- **Never publicly deploy** this local demo's built-in HTTP server or credentials. It is a synthetic demonstration, not production security software.
