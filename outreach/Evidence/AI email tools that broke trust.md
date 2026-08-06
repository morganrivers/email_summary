# AI email tools that broke trust

Documented incidents. These are the reference points to cite when someone asks why an architectural answer is needed rather than a policy promise. Each one is a case where the vendor was not malicious and it happened anyway, which is the strongest form of the argument.

## EchoLeak, CVE-2025-32711, Microsoft 365 Copilot

Zero-click indirect prompt injection. A single crafted email, with the payload hidden as an HTML comment or white-on-white text, caused Copilot to access internal files and exfiltrate their contents to an attacker-controlled server. No user interaction. CVSS 9.3. Disclosed by Aim Security in June 2025, patched server-side, and written up academically as the first real-world zero-click prompt injection in a production LLM system (arXiv 2509.10540).

The attack chained several bypasses: evading Microsoft's cross-prompt-injection classifier, defeating link redaction with reference-style Markdown, abusing auto-fetched images, and using a Teams proxy permitted by the content security policy.

**Why this matters to Letterlock.** This is exactly the threat `agentic_drafter.untrusted()` and `INJECTION_RULE` exist to blunt. It is also the best possible illustration that the danger is not only "the vendor reads your mail" but "anyone who emails you can steer the assistant that reads your mail." Most privacy pitches ignore this axis entirely.

## Superhuman AI exfiltrates emails

PromptArmor writeup, discussed on Hacker News 12 January 2026, 114 points, 31 comments. Same family of problem in a consumer email assistant.

The comment thread is worth reading in full, because it is your audience arguing your case:

- "You can have secure systems or you can have current gen LLMs. You can't have both."
- Criticism of permission granularity; a wish for per-operation approval rather than blanket access.
- "Programming used to prevent this by separating code from data. AI (currently) has no such safeguards."
- Direct question: why does an agent that summarises email need broad system access at all?

That last one is the strongest available framing for your least-privilege design. See [[Show HN]].

## Superhuman tracking pixels

Older but formative. Superhuman embedded tracking pixels in users' outgoing mail, exposing recipients' location and read behaviour to senders who never asked and recipients who never consented. Large HN threads in 2019. Superhuman was acquired by Grammarly in 2025.

**Why it matters.** It established, for this audience, that an email tool's incentives can quietly point against the people it touches. Anyone evaluating you will remember it.

## Gemini in Gmail and Workspace

A steady stream of complaint threads since 2024: features enabled by default, uncertainty about whether content feeds training, users unable to opt out cleanly, and at least one prominent "Ask HN: forced into Gemini on my Google account?" thread in 2026. Google's own guidance advises against entering confidential information into Gemini conversations, and says human reviewers see conversations disconnected from accounts. That advice is honest and it is also an admission your competitors cannot walk back.

## How to use this page

Not as an attack. As the answer to "why does this need to be built differently." Cite EchoLeak first, because it is a CVE with an academic paper attached, and nobody can dismiss it as marketing.

## Related

[[Evidence]] · [[Competitors and adjacent products]] · [[Privacy-conscious technical users]] · [[Show HN]]
