# Five-minute judge demonstration — ThreatX NEEDZERO

## The finding (30 seconds)
"In the supplied CRIMEATHON evidence, E04 showed that TallyBridge had excessive API permissions, while E18/E19 connected its credential to a vendor-bank change. Our prototype addresses the underlying issue: third parties had access they did not need for their approved job."

## Recreate the weakness in a synthetic environment (40 seconds)
Login as admin and paste the randomized TallyBridge test token from `.demo-credentials.txt`. Press **B · Request bank data**: the deliberately broad legacy contract allows a bank-field read (HTTP 200). Press **C · Attempt bank change**: on synthetic test data the account ending changes to `9083`.

## Experimental discovery (60 seconds)
Click **Run 6 Field Experiments**. The software removes each field from task inputs and reruns the approved contact-synchronization function across four test records. It finds that only `vendor_id`, `vendor_name`, and `phone` are required **for that defined task**. This is demonstrated experimentally, not assumed based only on job titles.

## Apply a real security restriction (40 seconds)
Click **Apply Experiment-Based Contract**. Python updates the stored policy: read only those three fields; no write access. Explain that the administrator reviews and activates the proposal; the engine does not automatically trust the third party's claimed purpose.

## Show the outcome (60 seconds)
- Press **A · Read contact data** -> HTTP 200; approved information only.
- Press **B · Request bank data** -> HTTP 403; no sensitive data returned.
- Press **C · Attempt bank change** -> HTTP 403; original master record does not change.
- Show Audit Trail including reasons for allowed and denied operations.
- Optionally set scope `V-0412`; after apply, another vendor's data is denied. Or revoke the key and demonstrate all access is denied.

## Conclude (30 seconds)
"Instead of merely detecting a suspicious transaction, our software experimentally determines what data a defined integration needs and enforces that reduced access. This allows the legitimate business function to keep working while protecting unnecessary fields and modifications. It is a local prototype tested with synthetic records, not a live deployment."

## Questions and grounded answers
**Is NEEDZERO the first of its kind?** No proven claim. Data minimization and least privilege exist; the distinctive prototype contribution is experimental, task-tested permission discovery directly linked to enforcement and measurable access results.

**Does this protect LedgerOne?** Only if all integration calls are routed through an enforced production gateway and direct bypass access is disabled. This demo protects its own fake database.

**Does one test prove a field is never required?** No. It only demonstrates necessity for the supplied task and fixtures. Real rollout requires a broader representative test suite and approval.

**What's the false-positive risk?** The experiment could remove fields needed in rare business situations. To reduce this, expand test scenarios, include fallback behavior and approve changes before deployment.

**How do you prove this isn't a static UI animation?** Open `core.py` and show the backend `authorize`, `read_vendor`, `write_vendor`, `discover_minimum_fields` and `apply_discovered_contract` functions. The browser makes real HTTP requests; verify 200 vs 403 and the SQL master record change before/after.
