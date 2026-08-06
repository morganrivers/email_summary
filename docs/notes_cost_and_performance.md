
● From cloud-api.near.ai/v1/models (unauthenticated, live now). USD per 1M tokens:

  ┌───────────────────┬───────────────────────────────┬───────┬────────┬────────────┬───────┐
  │       Model       │              id               │ Input │ Output │ Cache read │  Ctx  │
  ├───────────────────┼───────────────────────────────┼───────┼────────┼────────────┼───────┤
  │ GLM 5.2           │ z-ai/glm-5.2                  │ 1.40  │ 4.40   │ 0.30       │ 1.05M │
  ├───────────────────┼───────────────────────────────┼───────┼────────┼────────────┼───────┤
  │ DeepSeek V4 Flash │ deepseek-ai/DeepSeek-V4-Flash │ 0.17  │ 0.35   │ 0.035      │ 1.05M │
  ├───────────────────┼───────────────────────────────┼───────┼────────┼────────────┼───────┤
  │ Kimi K2.6         │ moonshotai/kimi-k2.6          │ 0.81  │ 3.85   │ 0.41       │ 262k  │
  ├───────────────────┼───────────────────────────────┼───────┼────────┼────────────┼───────┤
  │ Kimi K2.5         │ moonshotai/kimi-k2.5          │ 0.48  │ 2.20   │ 0.24       │ 128k  │
  └───────────────────┴───────────────────────────────┴───────┴────────┴────────────┴───────┘

  For reference, the other model this repo ships: openai/gpt-oss-120b at 0.15 / 0.55, cache 0.03.

  Cost per point of your first score column (input-weighted, roughly): DeepSeek V4 Flash is ~8x cheaper than GLM 5.2 for a 9% lower score. Kimi K2.6 sits between at about half GLM's input
  price and 88% of its output price.

  Two caveats:

  - These are the gateway catalog prices. llm_client.PROVIDERS deliberately uses the per-model direct endpoints (glm-5-2.completions.near.ai, gpt-oss-120b.completions.near.ai) because only
  those attest which model they serve. The catalog does not state whether direct-endpoint billing matches; Claude could not verify that without an authenticated call.
  - No Kimi endpoint is currently pinned in backend/integrations/inference_allowlist.json, and your table marks Kimi "attested 3p" rather than "nearai". Switching to one is not just a price
  decision, it needs a per-model attestation endpoint and a reviewed pin.

  Sources: cloud-api.near.ai/v1/models

✻ Sautéed for 51s

❯ what about glm5, glm5.1                                                                                                                                                                      

● Bash(curl -s --max-time 30 https://cloud-api.near.ai/v1/models | micromamba run -n py311 python -c "
      import json,sys…)
  ⎿  {
      "id": "z-ai/glm-5",
      "object": "model",
     … +174 lines (ctrl+o to expand)

● USD per 1M tokens:

  ┌─────────┬─────────────────────┬───────┬────────┬────────────┬───────┬─────────┬─────────────┐
  │  Model  │         id          │ Input │ Output │ Cache read │  Ctx  │ Max out │  owned_by   │
  ├─────────┼─────────────────────┼───────┼────────┼────────────┼───────┼─────────┼─────────────┤
  │ GLM 5   │ z-ai/glm-5          │ 1.05  │ 2.81   │ 0.52       │ 128k  │ ,       │ attested 3p │
  ├─────────┼─────────────────────┼───────┼────────┼────────────┼───────┼─────────┼─────────────┤
  │ GLM 5.1 │ zai-org/GLM-5.1-FP8 │ 1.40  │ 4.40   │ 0.26       │ 203k  │ 16k     │ nearai      │
  ├─────────┼─────────────────────┼───────┼────────┼────────────┼───────┼─────────┼─────────────┤
  │ GLM 5.2 │ z-ai/glm-5.2        │ 1.40  │ 4.40   │ 0.30       │ 1.05M │ 131k    │ nearai      │
  └─────────┴─────────────────────┴───────┴────────┴────────────┴───────┴─────────┴─────────────┘

  Three things worth noting beyond price:

  - GLM 5.1 and 5.2 cost exactly the same. Same input, same output, near-identical cache read. 5.2 gives 5x the context and 8x the max output on top. There is no price reason to run 5.1.
  - GLM 5 is cheaper but is attested 3p. Its description says "Attested model served via Chutes TEE (verified end-to-end by NEAR AI)", a different trust story from the two NEAR-operated ones.
  It also carries is_ready: false, as does Kimi K2.6 and most of the third-party set. is_ready: true appears on GLM 5.1 only, among the GLMs.
  - z-ai/glm-5.2 is what this repo already targets via the per-model endpoint glm-5-2.completions.near.ai, whose mr_td/rt_mr3 are pinned in backend/integrations/inference_allowlist.json.
  Moving to GLM 5 would mean pinning a Chutes-operated TD instead, so the allowlist would be vouching for a machine NEAR does not run. Given 5.2 costs the same as 5.1 and beats GLM 5 on your
  first column (40.1), the cheaper GLM 5 is the only one with an actual tradeoff, and it is a custody tradeoff rather than a quality one.

  Sources: cloud-api.near.ai/v1/models

Understood, I'll focus on reasoning, knowledge, instruction following, writing, and hallucination rather than coding. Let me gather the relevant numbers.Here is what I found. I've built the table around three benchmarks that Artificial Analysis measures uniformly across models, so the columns are comparable to each other: Humanity's Last Exam (hard reasoning and expert knowledge), IFBench (precise instruction following, which is the closest standard proxy for "does it actually do what I asked"), and the AA-Omniscience hallucination rate (how often a model guesses instead of abstaining when it does not know, lower is better).

| Model | Provider | HLE % | IFBench % | Hallucination rate % | Notes |
|---|---|---|---|---|---|
| GLM 5.2 | nearai | 40.1 | 73.3 | 28.1 | Best all-round of this set |
| DeepSeek V4 Flash | nearai | 36.8 | 79.2 | 84.4 | Sharp reasoning, very poor calibration |
| Kimi K2.6 | attested 3p | 35.9 | 76.0 | 39.3 | Strong balance |
| Kimi K2.5 (reasoning) | attested 3p | 29.4 | 70.2 | 64.6 | Non-reasoning mode: 12.3 / 43.7 |
| GLM 5.1 | nearai | 28.0 | 76.3 | 29.4 | Lower ceiling than 5.2, similar calibration |
| Qwen3.5 397B A17B | attested 3p | 27.3 | 78.8 | 89.1 | Excellent instruction following |
| GLM 5 (thinking) | attested 3p | 27.2 | 72.3 | 34.0 | Non-thinking mode: 7.2 / 55.2 |
| Qwen3.5 122B A10B | nearai | 23.4 | 75.7 | 85.5 | |
| Gemma 4 31B Instruct | nearai | 22.7 | 75.6 | 81.6 | |
| DeepSeek V3.2 (thinking) | attested 3p | 22.2 | 60.7 | 93.5 | Non-thinking mode: 10.5 / 49.0 |
| Qwen 3.6 27B | nearai | 21.6 | 67.5 | 48.3 | |
| Qwen 3.6 35B A3B | nearai | 20.2 | 64.3 | 49.7 | |
| MiniMax M2.5 | attested 3p | 19.1 | 71.6 | 89.3 | |
| GPT OSS 120B | nearai | 18.5 | 69.0 | 91.2 | Weakest calibration in the set |
| Qwen3 32B (thinking) | attested 3p | 8.3 | 36.3 | not published | Non-thinking mode: 4.3 / 31.5 |
| Qwen3-VL-30B-A3B-Instruct | nearai | 6.4 | 33.1 | not published | Vision model, 16K context here |
| Privacy Filter | nearai | n/a | n/a | n/a | Utility component, not a general model |

HLE and IFBench figures are Artificial Analysis measurements as of August 5, 2026, and the hallucination rates mirror the Artificial Analysis AA-Omniscience snapshot, which counts incorrect answers as a share of non-correct responses.

A few things worth reading into it:

**The hallucination column separates the field more than anything else.** GLM 5.2, GLM 5.1, GLM 5, and Kimi K2.6 are the only models here that abstain reasonably often. DeepSeek V4 Flash, Qwen3.5, MiniMax M2.5, and GPT OSS 120B will confidently invent an answer roughly nine times out of ten when they lack the knowledge, despite some of them reasoning well. If factual reliability matters more to you than raw reasoning ceiling, that narrows the list to about four models.

**Reasoning mode changes the picture substantially** for GLM 5, DeepSeek V3.2, Kimi K2.5, and Qwen3 32B. The non-reasoning numbers in the notes column are often less than half the reasoning ones, so how the endpoint is configured matters as much as which model you pick.

**On supplementary reasoning scores**, GPQA Diamond is largely saturated and less discriminating now, but for reference: GLM 5.2 sits at 91.2%, Kimi K2.6 at 90.5%, DeepSeek V4 Flash (max) at 88.1%, Kimi K2.5 at 87.6%, GLM 5.1 at 86.2%, and GLM 5 at 86.0%. Gemma 4 31B reports 84.3% and 85.2% on MMLU-Pro, and Qwen 3.6 27B reports 87.8% GPQA against 86.0% for the 35B-A3B. Those last few are vendor-reported rather than independently run, so they are not strictly comparable to the AA columns.

**On writing**, there is no widely-adopted standard benchmark with coverage across this particular set. IFBench is the nearest usable signal, since it measures adherence to formatting and phrasing constraints, which is what usually breaks in writing tasks. Human-preference arenas would be the other option, but most of these models are not ranked there.

Two gaps I could not close: Qwen3 32B and Qwen3-VL-30B-A3B-Instruct have no published AA-Omniscience result, and the Privacy Filter entry is not a general-purpose language model, so benchmark scores would not be meaningful for it.