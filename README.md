# Clef email classification demo

A Cloudflare Worker uses the Clef decision model to assess email addresses before it forwards signup requests.
D1 stores advisory decisions. The diagnostic backend receives the original request plus prediction headers.

**Public source does not mean a public live demo. Keep deployments behind Cloudflare Access.**
This standalone export contains synthetic examples, no customer email list, and no original Git history.
No deployment URL or credentials are supplied.

## Behavior

The model selects one of three verdicts:

* `likely_legitimate`
* `suspicious`
* `insufficient_evidence`

No verdict blocks a signup. Probabilities are model outputs, not validated fraud probabilities.
The policy uses visible address structure. It performs no DNS, reputation, domain age, or ownership checks.
The Apple relay domain instruction is a prompt rule, not a verdict override or proof of ownership.
Evaluate accuracy with approved, labeled data before any production use.

Clef runs synchronously before the backend receives the request. Latency includes inference and D1 writes.
The model deadline is 120 seconds. The browser sends sequential batches, with no signup retries.
There is no queue.

The proxy selects POST and PUT requests on these exact paths:
`/signup`, `/register`, `/AccountV2/ConfirmEmail`, and `/probe`.
Paths are case-sensitive. Trailing slashes do not match.
Other requests pass through, except the demo assets and inspection routes.

Input supports JSON, URL-encoded forms, and JSON encoded as `text/javascript`.
Extraction checks `email`, `emailAddress`, `email_address`, and `username`, including nested JSON objects and arrays.
The proxy preserves body bytes, method, path, query, cookies, authorization, Content-Type, and normal origin responses.
It replaces incoming `X-Clef-*` headers with committed prediction metadata.

| Condition | Behavior |
| --- | --- |
| Body exceeds 16 KiB | Return 413; do not forward |
| Body cannot be read | Return 400; do not forward |
| Invalid JSON, unsupported type, or no usable email | Commit `skipped`; forward unchanged |
| Missing HMAC secret or failed D1 commit | Return 503; do not forward |
| Model failure, invalid output, or deadline | Commit `error`; forward unchanged |
| Origin network failure | Return 502; do not retry |

A failed completion can leave a pending record. Origin requests and D1 commits are not one transaction.
The diagnostic backend creates no accounts and sends no email.

**Real origins must authenticate Worker traffic before they trust prediction headers.**
Use verified signatures or a shared secret, plus restrictions against direct origin access.
This demo does not implement that production boundary.

## Data and privacy

D1 stores request identifiers, timestamps, path, method, content type, email HMAC, and model decision metadata.
It does not store raw emails, request bodies, passwords, queries, cookies, or authorization headers.
Only the selected email goes to Workers AI. This still constitutes personal data processing.

`EMAIL_HMAC_KEY` produces HMAC-SHA-256 identifiers after trim and lowercase normalization.
Use at least 32 random bytes. HMAC identifiers are pseudonymous, not anonymous.
Secret rotation changes future identifiers.

**D1 records have no automatic expiry. Define a retention policy before real traffic enters the system.**
Observability is disabled. Keep sensitive values out of paths, content-type parameters, terminal output, and screenshots.
Probe commands print the supplied addresses. Use synthetic data only.

The browser uses eight synthetic inputs from `public/samples.json`.
All valid sample addresses use reserved example domains. No sample has an expected fraud verdict.
The sample schema contains `source.label`, `source.date`, `source.count`, `source.note`, and `emails`.
Inputs and results remain in page memory, not browser storage.

## Private deployment

**Use dedicated demo resources. Never send diagnostic requests to a production signup service.**
Confirm Clef availability, permissions, billing, and data terms in your account before use.

1. Run `npm ci`. Authenticate Wrangler with `npx wrangler login` or approved environment credentials.
   The templates omit `account_id`. Select the intended account and use that same account for `CF_ACCOUNT_ID`.
2. Replace `clef-demo.example.com` in both Wrangler files with your test hostname.
   Replace the zero `zone_id` and `database_id` with your resource identifiers.
   Keep `workers_dev` and `preview_urls` false.
   The origin uses a Worker Custom Domain. The proxy uses a Worker Route on that same hostname plus `/*`.
   Do not use a second Worker Route as the same-zone origin.
3. Before either deployment, create Access applications for the complete hostname and both Workers where applicable.
   Protect all paths, assets, and APIs. Add narrow authenticated Allow policies and approved identity providers.
   Do not add Bypass policies. Check for more-specific applications that could weaken protection.
   Add Service Auth for a dedicated service token if you need the live scripts.
4. Set the Access variables below. Run `npm run access` against dedicated demo applications only.
   The script requires existing applications, identity providers, and policies. It does not create them.
5. Create D1 and set its returned database ID in `wrangler.jsonc`. Apply the migration before proxy deployment:

   ```sh
   npx wrangler d1 create clef-signup-classifications
   npm run db:migrate
   ```

6. Set the HMAC secret before proxy deployment. Supply at least 32 random bytes from your secret manager:

   ```sh
   npx wrangler secret put EMAIL_HMAC_KEY
   ```

   A new Worker can require creation before Wrangler stores its secret. Check its name, account, and Access protection first.
7. Deploy the diagnostic origin, then the proxy:

   ```sh
   npm run deploy:origin
   npm run deploy
   ```

   `deploy` configures Access before and after deployment. This sequence is not an atomic security transaction.
   `deploy:origin` deploys only the origin. Its Access protection must already exist.
8. Verify anonymous denial for `/`, `/app.js`, `/samples.json`, and the API. Verify authenticated requests succeed.
   Run the live scripts only against your private diagnostic deployment.

No Transform Rule or redirect is required.
The optional diagnostic marker uses `X-Demo-Clef-Integration: worker-route`. It does not select the Worker or authenticate traffic.

For real integration, retain the existing authenticated origin instead of the diagnostic backend.
Narrow the route and `SIGNUP_PATHS` to your endpoints. Validate extraction against your real payload schema.
Review privacy, retention, latency, error policy, and model accuracy before cutover.

## Environment and commands

**The Access script replaces every Allow policy's include rules and clears its require/exclude rules.**
Use dedicated applications only. Review the configured domains before execution.
The script refuses absent Allow policies or any Bypass policy. It preserves existing Service Auth policies.
It verifies saved Allow rules, but does not prove complete hostname coverage.

`npm run access` and `npm run deploy` require:

| Variable | Value |
| --- | --- |
| `CF_ACCOUNT_ID` | Account with the existing Access applications |
| `CF_ACCESS_API_TOKEN` | API token with Access read and edit permissions |
| `CF_ACCESS_APP_IDS` | Comma-separated application IDs |
| `CF_ACCESS_IDP_IDS` | Comma-separated approved identity provider IDs |
| `CF_ACCESS_EMAIL_DOMAINS` | Comma-separated approved email domains |

Wrangler authentication is separate from the Access token. Scripts use environment variables, not personal credential stores.

`npm run smoke` and `npm run test:emails` require:

* `DEMO_BASE_URL`: the private demo origin, such as `https://clef-demo.example.com`.
* `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET`: the approved Access service token.
* Wrangler authentication with remote D1 read permissions in the configured account.

Smoke also requires `ACCESS_TEAM_DOMAIN`, such as `your-team.cloudflareaccess.com`, without a scheme or path.
It checks real inference, D1 commits, backend prediction receipt, request preservation, and anonymous Access denial.
Its report goes to ignored file `results/live-smoke.json`.

```sh
npm test
npm run dev
npm run records
npm run smoke
npm run test:emails
npm run test:emails -- alice@example.com invalid-input
```

`npm test` runs deterministic local tests. Local development does not verify deployment security or real inference.
The email probe prints inputs and results. It writes no report file.
This export does not claim a new live deployment or production accuracy.

## Export verification: 2026-11-12

* All six local tests pass. Both Workers pass Wrangler dry-run builds.
* Browser checks cover synthetic sample controls, the batch limit, and desktop/mobile layouts.
* A local smoke uses the exported Worker, in-memory SQLite, and the diagnostic backend over HTTP.
  Invalid input commits a skipped record. The backend receives the original body, path, and committed predictions.
* Scripts reject absent environment settings before live requests. Probe help works without credentials.

These checks do not exercise live Clef inference, a new Cloudflare deployment, customer authentication, or production accuracy.

## References

* [Clef model and API](https://developers.cloudflare.com/workers-ai/models/clef/)
* [Worker Routes](https://developers.cloudflare.com/workers/configuration/routing/routes/)
* [D1 database bindings](https://developers.cloudflare.com/d1/worker-api/d1-database/)
* [Access for Workers](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
* [Access policy selectors](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
* [Access email one-time PIN](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/)
* [Apple relay domain](https://support.apple.com/en-qa/105078)

## Changes

* Exported the current source with fresh history and synthetic samples. Excluded customer data and private deployment details.
* Replaced resource identifiers with templates and personal credential lookups with explicit environment variables.
* Retained the advisory Clef policy, D1 records, backend inspection, and private deployment requirements.
