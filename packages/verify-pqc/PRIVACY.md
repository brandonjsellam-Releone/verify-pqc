# pqtrace — Privacy / GDPR / FADP deployment guidance

Distilled from the council privacy review (Mistral seat, European/GDPR lens, 10 Jul 2026). This is
deployment guidance for integrators, **not** legal advice and **not** a compliance certification.
pqtrace **supports** record-keeping obligations (e.g. EU AI Act Art. 12); it does not certify them.

## 1. What is and is not in the trace

- **Committed (not readable from the trace):** step *content* — stored as `HMAC-SHA512(salt, content)`
  with a 32-byte salt held by the trace owner. Low-entropy prompts cannot be dictionary-attacked from
  the trace, and the HMAC construction binds the salt/content boundary (no suffix-only disclosure).
- **Plaintext (readable from the trace):** `kind`, `actor`, `model_id`, `model_config_hash`,
  `tokens`, `tool_name`, `policy_id`, `ts`, `trace_id`, `session_id`, `runner`, and the `meta` blob.

**These plaintext fields can be personal data.** `session_id` + `ts` patterns + token counts +
step-kind sequences can enable behavioural fingerprinting / singling-out (CJEU *Breyer* C-582/14;
EDPB Opinion 05/2014). Therefore, deployment MUST:

- Set `actor` to a **pseudonymous** id (a random/opaque handle), never a raw natural-person
  identifier, unless there is a lawful basis and the DPIA covers it.
- Treat `meta` as **plaintext** — never place prompt/output substance or PII in `meta`; put content
  only in the committed `content` parameter. Consider schema-validating `meta` to block PII.
- Default `session_id` to `null` unless linkage across a conversation is genuinely required.
- Run a **DPIA** where traces enable systematic monitoring, and record the activity in the RoPA.

## 2. Terminology — we do NOT claim anonymization

A salted commitment is **pseudonymisation**, not anonymisation (EDPB Opinion 05/2014). Docs and
marketing must say "committed" / "pseudonymised", never "anonymised". No "GDPR-compliant" claim —
only "supports GDPR/FADP compliance obligations."

## 3. Right to erasure vs the append-only anchor

The RFC-6962 anchor is immutable by design; the sealed HEAD carries `trace_id`/`session_id`/`runner`
+ hashes. **Crypto-erasure** (destroying the content salt so a commitment can never be opened) is a
*supporting* erasure measure, not a guaranteed Art. 17 erasure — the EDPB (Guidelines 01/2023)
requires erasure to be effective/unrecoverable. Deployment guidance:

- Keep a separate **mutable erasure register** that marks a `trace_id` as erased (soft-deletion)
  while the immutable anchor is preserved for integrity.
- On an erasure request, **destroy the salts** for the affected content steps (crypto-erasure) and
  record it in the erasure register.
- Prefer a **private** log by default; use a shared/public transparency log only when public
  verifiability is explicitly required and the personal-data surface has been assessed.
- Apply a **retention policy** to salts + content stores; document it.

## 4. Salt custody (mandatory discipline)

Salts are the disclosure keys. **Losing** them = permanent inability to open content (functional
loss); **leaking** them = dictionary exposure of low-entropy content. Therefore:

- Store salts in an HSM / secure enclave, separate from the trace store.
- If a third party (not the owner) holds salts, that party is a data processor — put an Art. 28
  agreement in place.
- Consider splitting salts (secret-sharing) across owner + a trusted custodian to avoid a single
  point of loss/leak.

## 5. Switzerland (FADP) specifics

- `session_id` + `ts` + `tokens` used to analyse behaviour may constitute **profiling** (Art. 5
  FADP) — check consent basis.
- Consider **data-localisation** expectations for Swiss users' data; a CH-resident log node may be
  required for some deployments.

## 6. Bottom line

pqtrace is privacy-*capable* (content committed + salted) but not privacy-*by-default-at-the-metadata-
layer*. A compliant deployment pseudonymises `actor`, keeps content out of `meta`, minimises
`session_id`, runs a DPIA, manages salts in an HSM, and pairs the immutable anchor with a soft-delete
erasure register. The module ships the crypto; the deployment owns the posture.
