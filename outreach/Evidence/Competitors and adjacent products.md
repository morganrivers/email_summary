# Competitors and adjacent products

Who else claims private AI, and where the claim actually stops. Written to be honest rather than flattering to Letterlock, since the whole positioning depends on precision.

## Direct: AI email assistants without a confidentiality architecture

| Product | Position | Where the gap is |
|---|---|---|
| **Gemini in Gmail** | Default, free, enormous | Google's own guidance warns against entering confidential information; human reviewers see conversations disconnected from accounts. The tool is inside the mail provider, so there is no boundary to point at |
| **Microsoft 365 Copilot** | Enterprise default | EchoLeak (CVE-2025-32711) demonstrated zero-click exfiltration through a crafted email. See [[AI email tools that broke trust]] |
| **Superhuman** (Grammarly) | Premium speed | Tracking-pixel history, and a 2026 exfiltration writeup |
| **Shortwave** | AI-native Gmail client | Conventional cloud processing |

Against these, the differentiator is architectural and easy to state without exaggeration: they can read the content, you have arranged not to be able to.

## Adjacent: privacy brands adding AI

**Proton Scribe.** Proton's writing assistant, positioned explicitly as a private alternative to Gemini and Copilot, open-source models and code, auditable. The most credible competitor on this page, with a brand this audience already trusts and a business model that does not depend on reading mail. Their constraint is the interesting one: Proton Mail's end-to-end encryption limits how much context an assistant can have, and assistance without context is a thin product. Letterlock's enclave approach is a different answer to the same tension. Expect to be compared to them constantly, and expect the comparison to be fair.

**ExpressAI** (ExpressVPN). Rolled out from 31 March 2026, built on confidential computing, with the claim that not even ExpressVPN can access conversations. Notable because it proves the confidential-computing consumer pitch is now mainstream enough for a VPN company to spend marketing money on it. Not email-specific.

**OpenGradient Chat.** Launched June 2026. Routes to frontier models through local encryption, Oblivious HTTP and secure enclaves so prompts are not linked to identity. Different threat model: anonymity rather than confidentiality.

**Opaque, Edgeless Systems, and the enterprise confidential-AI vendors.** Sell platforms, not products. Potential allies rather than rivals. Edgeless runs OC3 in Berlin. See [[Confidential Computing Consortium]] and [[Berlin]].

## Adjacent: privacy email providers

Posteo, mailbox.org, Tuta. Not competitors today, since none of them offers an AI assistant, and structurally cannot for encrypted mailboxes. Discussed as potential distribution in [[Berlin privacy companies]].

## The honest competitive summary

Two sentences you can say without rounding anything up:

1. Against the mainstream assistants, the difference is real and structural: their business requires reading the content, and yours is arranged so it cannot.
2. Against Proton, the difference is narrower and mostly about how much context an assistant gets to work with, and pretending otherwise in front of a technical audience will cost you more than admitting it.

## Related

[[Evidence]] · [[AI email tools that broke trust]] · [[SaaSHub and AlternativeTo]] · [[Berlin privacy companies]]
