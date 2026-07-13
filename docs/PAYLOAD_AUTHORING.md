# Authoring Payloads

Payloads are declarative YAML test cases loaded by `PayloadRegistry`. Keeping them
as data (not code) means you can extend coverage — including from vetted public
research — without touching the engine, and review test changes in version control.

## Schema

```yaml
- id: PI-001                 # unique, stable; namespace by category (PI/SPE/DL/II/JB)
  category: prompt_injection # prompt_injection|jailbreak|system_prompt_extraction|
                             # data_leakage|indirect_injection|denial_of_service
  name: Direct instruction override
  description: >
    What boundary this tests and why.
  template: |
    The text sent to the target. May contain the {canary} placeholder.
  detection: canary          # canary|signature|refusal|llm_judge
  success_indicators: []     # for `signature`: strings that imply success
  refusal_indicators: []     # phrases that imply the model refused
  severity_base: 6.5         # 0–10; scoring dampens this by detection confidence
  references: []             # OWASP LLM Top 10 / CWE / paper / disclosed report
  tags: []
  enabled: true
```

## Choosing a detection strategy

- **`canary` (best).** Put `{canary}` in the template. A positive is provable and
  reproducible — the marker cannot appear by chance. Prefer this whenever the
  attack can be made to echo a token.
- **`signature`.** When success has a recognisable shape but no marker (e.g. a
  leaked system prompt containing "You are …"). Provide `success_indicators` and
  `refusal_indicators`; the detector weighs them and returns INCONCLUSIVE on a
  mixed signal rather than over-claiming.
- **`refusal`.** Only decides refuse/not-refuse; non-refusal is INCONCLUSIVE, not
  vulnerable. Use as a cheap pre-filter, not as sole proof.
- **`llm_judge`.** For semantic outcomes (subtle data leakage). Off by default and
  egresses target data to a third party unless you configure a local backend.

## Good practice

- One behaviour per payload; let dedup (roadmap B3) collapse related hits.
- Make success **observable**: prefer canary echo or a concrete indicator over
  vibes.
- Set `severity_base` from real impact (OWASP LLM Top 10 is a good anchor), and
  trust the confidence-dampened scorer to keep low-confidence hits honest.
- Always cite `references` — reproducibility and triage both depend on provenance.
- Namespace imported payloads (e.g. `GARAK-…`) and record the source.

## Importing from public research

The engine is a harness; upstream corpora are the ammunition. To bring in probes
from Garak, PyRIT, papers, or your program's disclosed reports:

1. Map each probe to the schema above (template + detection + references).
2. Namespace the `id` and record provenance in `references`.
3. Start with `enabled: false`, review, then enable.
4. Add/adjust `refusal_indicators` for your target's locale.

## Testing a new payload

Extend the mock (`tests/fixtures/mock_ai_app/app.py`) with a matching
vulnerable/secure behaviour so you have ground truth, then assert in an
integration test that the payload fires in vulnerable mode and stays quiet in
secure mode. That's how precision is proven rather than assumed.
