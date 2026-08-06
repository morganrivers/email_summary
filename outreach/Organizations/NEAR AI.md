# NEAR AI

**Status:** not started
**URL:** near.ai

Confidential inference infrastructure. The `nearai-glm` and `nearai-gpt-oss` providers in `llm_client.PROVIDERS` are theirs, so the confidential route depends on their enclaves and on the measurements pinned in `backend/integrations/inference_allowlist.json`.

## Recent, and relevant

- **IronClaw 1.0**, released late July 2026, is the open-source agent runtime behind their confidential stack
- **Venice.ai** integrated for fully private inference in March 2026
- Joined NVIDIA Inception in January 2026; partnerships include Brave and a sovereign-workload deal with Bermuda

They are building the exact category you are building on top of, and they publicise integrations. A production application that verifies their attestations properly, and that documents where their measurements fall short, is worth something to them.

## The unresolved technical point

Your own notes say it: RTMR3 measures NEAR's bootstrap compose, not the model server, and you close that gap with the ComposeLog action-log quote. That is a genuine finding about their platform. Reporting it to them directly is both good practice and the most credible possible introduction.

## Related

[[Organizations]] · [[Phala Network]] · [[Confidential Computing Consortium]]
