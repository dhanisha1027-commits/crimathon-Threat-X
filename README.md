# ThreatX NEEDZERO — Local Working Security Software

**CRIMEATHON'26 / Case CR-26-047 / Defense approach**

This project demonstrates a *counterfactual access-testing* approach on fictional vendor data. It experimentally removes fields from a defined contact-sync task, then **enforces** the resulting minimum-read, zero-write contract in a Python API gateway. It also supports vendor scope, credential expiry, revocation, audit trails and an interactive browser playground.

## Prerequisites

- Python **3.10 or newer**
- VS Code or any text editor
- **No Python libraries need to be installed** (standard library only)

## Start on Windows

1. Extract the ZIP and open the `ThreatX_NEEDZERO` folder in VS Code.
2. Open Terminal -> New Terminal.
3. Run:

   ```powershell
   py -3 seed_demo.py
   py -3 app.py
   ```

   If `py -3` is unavailable, use `python` instead.
4. Open **http://127.0.0.1:8765** in your browser.
5. Find your admin username/password and synthetic integration token in `.demo-credentials.txt` in the same folder. Paste the token in **Live API Playground**.

## Start on Kali Linux

```bash
python3 seed_demo.py
python3 app.py
```

Open **http://127.0.0.1:8765**. Use `cat .demo-credentials.txt` to view the test credentials.

## Demonstration (before versus after)

1. **Show the problem**: Log in; in the API Playground, paste the integration token. Press **B · Request bank data**. This intentionally overprivileged *synthetic legacy* policy exposes the masked bank account. Press **C · Attempt bank change** to simulate E18/E19 on a fake record. The masked bank value in Master Records changes from `****4417` to `****9083`.
2. **Discover necessary data**: Click **Run 6 Field Experiments**. The engine removes each field from four synthetic vendor records and checks that the defined contact sync still produces the exact baseline output. It determines `vendor_id`, `vendor_name`, `phone` are necessary for the *tested task* and the rest are not.
3. **Apply actual restriction**: Click **Apply Experiment-Based Contract**. The server updates its stored integration contract to read only those three fields and **write no fields**.
4. **Demonstrate authorized access**: Press **A · Read contact data** → HTTP 200 and only the three approved values.
5. **Demonstrate forbidden access**: Press **B · Request bank data** → HTTP 403. Press **C · Attempt bank change** → HTTP 403; the master bank value remains unchanged.
6. **Optional scoped access**: Set Allowed vendor IDs to `V-0412`, apply again, and press **D · Request different vendor** → HTTP 403.
7. **Revoke the credential**: Click Revoke and repeat test A → HTTP 403. Show Audit Trail entries and reasons.

The post-contract restrictions are **real backend checks**, not UI-only labels.

### Reset the local demo

Stop the server (`Ctrl+C`). Delete `data/threatx.sqlite` and `.demo-credentials.txt`, then run `python seed_demo.py` and `python app.py` again. The new credentials will be random.

## Test automatically

```bash
python -m unittest discover -s tests -v
```

Tests cover the experimental field discovery, access before and after tightening, sensitive write denial, vendor scope, expiry, revocation and the audit trail. Tests use a temporary SQLite database, not your main demo data.

## What makes the approach distinct?

Conventional RBAC usually grants permissions written by an administrator. This prototype *empirically tests* whether a specific approved task can function with less data, produces a necessity report, and lets an administrator activate that reduction as an enforced policy. It is **not a claim of global invention or production-ready security**; data minimization, least privilege and software testing are established ideas.

## Architecture

```
Synthetic Vendor DB -> Necessity Experiment -> Admin Review / Apply
                                              |
Third-party API token -> Policy Gateway -------+---> Permitted fields only
                          |                     +---> Deny restricted reads/writes
                          +---> Access Audit Trail
```

## Evidence connection

- **E04** records TallyBridge's excessive key permissions.
- **E18 + E19** record a third-party-key request matching a vendor-bank change via request ID `req-5f61b0de8`.
- The software shows a *local reproduction* using **synthetic** vendor V-0412 and fake account endings. It does not connect to LedgerOne, TallyBridge or other real services.

## Explicit limitations

- This is a **local educational prototype**, not production-ready security. Python's `http.server` must not be exposed to the internet. It deliberately runs only on `127.0.0.1` and provides no HTTPS, distributed-session hardening or production authentication controls.
- **The synthetic legacy credential is intentionally overprivileged** to reproduce the case, so do not use it with real records or host this app publicly.
- The permission-minimization test only supports a **defined contact-sync task** and a few synthetic fixtures. It cannot infer what an arbitrary third-party application needs in all possible scenarios. Human review, comprehensive workflow tests and ongoing monitoring are required.
- The master database and gateway are both owned by this demo. To protect LedgerOne in reality, *all* third-party access would need to be forced through an enforced gateway, with direct database/API bypass paths disabled.
- Masked account endings are demonstration data. This prototype does **not** implement bank-account encryption, enterprise IAM, MFA, secret management, safe deployment, anti-brute-force controls or formal transaction approval.
- An allowed API caller may copy data after receiving it. Field-level access restrictions cannot retroactively remove that copy.

## Files

- `app.py` – local web server, admin console, and integration API endpoints
- `core.py` – SQLite records, tokens, policy enforcement, experiment engine and audit
- `seed_demo.py` – safe fake data, randomized local demo credentials
- `static/` – responsive HTML/CSS/JavaScript interface
- `tests/` – offline automated checks
