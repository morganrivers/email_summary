# Messaging kit

Working file for website copy, outreach, bio, and launch material.
Source voice: `~/voice-dna-email.md`. Source architecture: `docs/plan.md`.

Rules carried over from the voice profile, applied to marketing register:

- No em-dashes. Parentheses do that work.
- No hyperbole ("amazing", "revolutionary", "game-changing").
- Every claim carries its limit in the same paragraph.
- Specific numbers, named vendors, named failure modes.
- Warm but reserved. One exclamation mark per document, at most.
- No jargon that is not defined on first use.

---

## 1. One decision left before writing more copy

### 1a. Product name: settled

The name is **Letterlock**, at `letterlock.ai`. `letterlockai.com` is held
alongside it and redirects to `letterlock.ai`, so the obvious mistyping of the
domain does not land on someone else.

Both earlier candidates are dead, and for the same reason each time: the name
was already occupied in this exact category.

- **Faraday** is out. `faraday.email` is a live AI email client marketing on
  privacy, no training on user mail, AES-256, Gmail and Outlook support. The
  cage metaphor was the best fit for the claim, but the name is taken by a
  direct competitor with the better domain.
- **Fortress** is out. `fortress.email` is registered, and the metaphor was
  wrong anyway: a fortress keeps attackers out, while the differentiated claim
  is that the operator on the inside cannot look in.

Two things to hold to, given "lock" is doing the security work in the name:

- Keep the visual identity off padlocks, vaults, chains, and safes. Every
  security product uses that imagery, so it identifies the category rather than
  the product, and it invites the comparison to encrypted-mail vendors whose
  claim is stronger than ours. Run TSDR and EUIPO before printing anything.
- A lock connotes impenetrability, and the threat model has gaps that are stated
  plainly (Scaleway sees masked text, masking recall is not 100 percent, Google
  sees everything regardless). Let the copy carry the security claim, qualified,
  rather than the name. See the honesty ladder in section 2.

Known cost, accepted: `.ai` is not the default guess for a domain, so the TLD
has to be said explicitly every time the name is spoken.

### 1b. Gmail in the tagline

You asked whether to keep Gmail in the tagline. **Keep it.**

- It is honest. The product does not work with Outlook, Apple Mail, or Proton,
  and the About page already says so. Discovering that after clicking is worse
  than being told up front.
- It qualifies traffic. You want the 4 people out of 100 who have Gmail and
  care about security, not the 40 who bounce at the pricing page.
- It is the searchable term. "Gmail AI assistant" is a phrase people type.
  "Secure email AI" is not.
- Narrow claims read as more credible than broad ones, which is the entire
  positioning.

The cost is that it caps the perceived ambition. Fix that in the second line,
not by removing the word.

---

## 2. The honesty ladder

The core risk in this project is that the security claim is the product, so a
single overstatement destroys the thing you are selling. Sort every claim into
one of these four tiers before it goes on a page.

**Tier 1: provable, hardware-backed.**
Say these plainly and link the proof.

- The server runs inside an Intel TDX enclave on Phala.
- The enclave emits a signed attestation report at boot naming the code hash.
- The Gmail OAuth token is sealed and released only after attestation passes.
- The source is public and the build is reproducible, so anyone can rebuild
  and compare hashes.

**Tier 2: true, but with a stated boundary.**
Always ship these with the boundary in the same sentence.

- "PII is masked before text leaves the enclave" plus "recall is not 100% and
  the test corpus is public".
- "Inference runs in the EU on open-weight models" plus "Scaleway is a normal
  cloud vendor, not an attested one, so that hop is jurisdiction plus contract,
  not hardware proof".
- "We cannot read your mail" plus "Google still can, because it is Gmail".

**Tier 3: roadmap, label it as roadmap.**

- Inference inside an attested GPU enclave, which is what would close the
  Scaleway gap.
- Third-party audit of the masking recall.
- Published attestation-verification tooling a non-expert can run.

**Tier 4: do not say.**

- "Provably never leaks your data." Your own plan document says masked text
  goes to a non-attested third party. The word "never" is not yours to use yet.
- "Zero-knowledge", "military-grade", "unhackable", "your data never leaves
  your device".
- Any comparison claiming a named competitor is insecure. Compare on published
  architecture only, and link their docs.

Suggested replacement for the front-page superlative:

> Letterlock is open-source agentic email that runs where the operator cannot look.

That is defensible today. "Never leaks" is not.

---

## 3. Is it technically feasible

Short answer: the architecture is feasible and mostly already reasoned through
in `docs/plan.md`. The gap is not technical, it is that the strongest version
of the marketing claim is one component ahead of the build.

**Solid:**

- Intel TDX on Phala dstack, sealed secrets gated on attestation, RA-TLS
  binding. This is a well-trodden path and the plan already scopes it at about
  one day for attestation plus sealed secrets.
- Reproducible Nix build producing a comparable image hash. `flake.nix` exists.
- Gmail OAuth, drafts-only write scope, per-account credential isolation.
  Already built and running.

**The real gap:**

- Model inference is on Scaleway, outside the enclave. So the true statement is
  "one EU vendor sees masked text", not "nobody sees anything". Every marketing
  sentence has to survive that fact. Closing it needs attested GPU inference
  (TDX plus confidential computing on H100/H200 class hardware), which exists
  but costs materially more per token.
- Masking recall. NER-based PII stripping catches names, emails, and phone
  numbers. It does not catch "the Series B term sheet from the Munich fund".
  Semantic content is still sensitive and still leaves. Say so.
- Shared tenancy. One enclave holds all users' tokens, so cross-tenant
  isolation is a property of your code, and attestation says nothing about
  whether your code is correct. This deserves a paragraph on the About page,
  because a security-literate reader will ask.
- Google sees everything anyway. The honest framing is "Letterlock adds no new
  party who can read your mail", not "your mail is private". The former is
  true and still valuable. The latter invites a dunk.

**Verdict for the copy:** you can ship "the operator cannot read your mail, and
you can verify that in hardware" today. You cannot ship "your data never
leaves" until inference is in-enclave. Put the second one on a public roadmap
with the reason, which is itself good marketing for this audience.

---

## 4. Bio

Facts on record: engineering physics at Tufts, graduate coursework in
experimental physics at MIT, electro-optic engineer in Cambridge MA, researcher
at ALLFED on grid resilience, HEMP, backup communications, and critical
infrastructure fragility, master's in climate physics and sustainability at
Potsdam.

You mentioned satellite and defense work. Fill in the employer name and years
before publishing, since a vague gesture at defense work reads worse than a
specific one.

**One line (bylines, launch sites, forum signatures):**

> Morgan Rivers builds Letterlock. Previously an electro-optic engineer on
> satellite systems, and a researcher on critical-infrastructure resilience
> at ALLFED.

**Short (about page, ~60 words):**

> I am Morgan Rivers. I studied engineering physics at Tufts and experimental
> physics at MIT, then worked as an electro-optic engineer on satellite systems
> at [COMPANY]. After that I spent several years at ALLFED researching how
> critical infrastructure fails: grid collapse from geomagnetic storms,
> communications after an EMP, food supply chains under industry loss. I am
> now finishing a master's in climate physics at Potsdam.

**Long (blog, investor note, ~140 words):**

> I am Morgan Rivers, based in Berlin. My background is physics and hardware.
> I studied engineering physics at Tufts, did graduate coursework in
> experimental physics at MIT, and worked as an electro-optic engineer on
> satellite systems at [COMPANY], where I learned what it looks like when a
> system has to work without anyone being able to reach in and fix it.
>
> For the last several years I have worked at ALLFED on how critical
> infrastructure fails and how it might be made to fail more gracefully:
> the effect of geomagnetic storms on the power grid, backup communication
> systems, food production after loss of industry. That work made two things
> obvious to me. Systems fail at their interconnections, and centralisation
> that looks efficient in normal times is the thing that turns a local
> failure into a general one.
>
> Letterlock is the same argument applied to email.

The last line is the reason the bio belongs on the site at all. The physics
credential is not the point. The infrastructure-fragility credential is the
point, because it explains why you specifically noticed this problem.

---

## 5. Elevator pitches

**Ten seconds:**

> Letterlock is an open-source AI assistant for Gmail that runs inside a hardware
> enclave, so I cannot read your email even if I wanted to.

**Thirty seconds:**

> Every AI email assistant today asks you to trust a company's privacy policy.
> Letterlock replaces that with a hardware proof. It runs inside an Intel TDX
> enclave, which produces a signed report saying exactly which code is running,
> and the code is public so you can check the hash yourself. It drafts replies,
> checks your calendar, and summarises your inbox. It never sends anything
> without you.

**Sixty seconds, adds the why:**

> I spent several years researching how critical infrastructure fails. The
> pattern is always the same: things that were separate get connected, the
> connection is efficient, and then one failure propagates everywhere.
>
> AI assistants are that pattern applied to personal data. Your email, your
> calendar, your documents, and your messages were in separate silos with
> separate failure modes. An assistant links them all and ships the combined
> thing to one company's servers. That is a much better target than any of the
> silos was, and the models good enough to be useful are also good enough to be
> used offensively.
>
> Letterlock is the same product built so that the operator is not a trusted
> party. It runs in a hardware enclave that proves which code it is executing,
> the code is open source, and personal identifiers are stripped before
> anything reaches a model. It works with Gmail, it drafts but never sends, and
> it costs 20 euros a month.

---

## 6. Front page

Your draft, with the Tier 4 claim removed and the argument tightened. The
diagnosis in the middle is the strongest thing you have written so far, so it
should stay near the top rather than being buried under features.

```
Letterlock is agentic email that the operator cannot read.

Open source. Runs in a hardware enclave. Works with Gmail.

[ Join the waitlist ]   [ Read the threat model ]

---

AI assistants are the worst case for personal data security.

They do the one thing you would tell an attacker to do. They link silos that
were previously separate (mail, calendar, contacts, documents), and they ship
the combined result to a large centralised server under an opaque data policy.
Each silo used to fail on its own. Now they fail together.

The risk compounds as models get better at finding and exploiting weaknesses,
because the same capability that makes an assistant useful makes a breach
more effective.

The fix is not to hide the code.

Letterlock runs inside an Intel TDX enclave, a region of the processor that the
host operating system, the cloud provider, and I cannot inspect. At boot the
enclave signs a report naming the exact code it is running. The source is
public and the build is reproducible, so you can rebuild it and check that the
hash matches. This is a claim you can verify, not a promise you have to accept.

---

What it does
- Drafts replies in your voice, with context pulled from your own mail history
- Checks your calendar, proposes times, creates events on confirmation
- Tells you on Telegram when a draft is ready
- Optionally includes a full trace of every tool it called and every source
  it read, inside the draft itself
- Runs on open-weight models hosted in the EU

What it does not do
- It does not send mail. It writes drafts. You send.
- It does not work with Outlook, Apple Mail, or Proton.
- It does not store your mail.

What is not yet proven
Model inference runs on Scaleway in France, outside the enclave. That vendor
sees text with personal identifiers stripped, but stripping is not perfect and
the remaining text still carries meaning. Moving inference inside an attested
GPU enclave is the next milestone. Until it lands, this page will keep saying so.
```

That last block is the single highest-value paragraph on the site for this
audience. Nobody in security believes a page with no caveats.

---

## 7. Waitlist page and the offer

Goal: collect emails while building. Keep the offer small and concrete. Large
offers from a solo pre-launch product read as either desperate or dishonest.

**Page:**

```
Letterlock is not open yet.

I am building an AI assistant for Gmail that runs inside a hardware enclave,
so that the person operating it (me) cannot read your mail. The code is open
source and the enclave proves which version it is running.

Leave your email and you get:
- The threat model document, before it is public
- An invitation when the private beta opens, in order
- Founding price of 10 euros a month for the first year, half the list price

[ email field ]  [ Join ]

I will email you when there is something to say, and not otherwise.
No more than once a month.

Building in public: [repo link]. Open issues and disagreement welcome.
```

Notes on the offer:

- "The threat model doc before it is public" is the right lead magnet for this
  audience, and it costs you nothing because you have to write it anyway.
- Founding price is honest and finite. Avoid "free forever", which you cannot
  afford at 20 euros of inference-bearing cost.
- "No more than once a month" is a promise you must actually keep. This
  audience notices.

---

## 8. Blog post: why I am building this

Title options:

- "AI assistants are a centralisation problem, not a privacy problem"
- "The assistant is the attack surface"
- "I researched how infrastructure fails. Then I looked at my inbox."

Recommended: the third. It is specific to you, and nobody else can write it.

**Outline:**

1. The ALLFED work in one paragraph. Geomagnetic storms and the grid. What you
   actually found: interconnection is the failure mechanism, and efficiency
   pressure removes the buffers that used to contain failures.
2. The analogy, stated once and not laboured. Your personal data used to be
   siloed by accident, and those accidental silos were doing real work.
3. What an assistant does to that. Names the specific new capability: a single
   credential that reads everything and acts on your behalf.
4. Why "we take privacy seriously" is not an answer. Policy is revocable,
   acquirable, and subpoenable. Code that is attested is none of those.
5. Why the answer is not secrecy. Closed source means the claim reduces to
   trusting the operator, which is exactly the thing being replaced.
6. What Letterlock actually is, and what it is not yet. Include the Scaleway gap
   here. Ending a manifesto on an admitted limitation is unusual and is the
   most persuasive move available to you.
7. One line asking for the waitlist. One line only.

**Opening draft:**

> For several years I worked on a question that sounds abstract until you look
> at the numbers: what happens to a country when its electrical grid goes down
> and does not come back for a year. I modelled geomagnetic storms hitting
> high-voltage transformers, food production after loss of industry, and what
> communication would look like after a high-altitude EMP.
>
> The finding that stayed with me was not about any single failure. It was
> that the damage is almost never proportional to the initial event. It is
> proportional to how tightly the system was coupled beforehand. Systems that
> had been optimised, consolidated, and interconnected turned local problems
> into general ones.
>
> I now think personal data is going through exactly that consolidation, and
> that AI assistants are the mechanism.

---

## 9. Emails

### 9a. To David (asking for security contacts and his Signal number)

Peer-professional register: Hi, contractions, closes on "Thank you," because
there is an ask.

> Hi David,
>
> Thank you for the time on [DATE], the point about attestation being useless
> if nobody actually verifies it has been sitting with me since.
>
> I am building the thing we discussed, an open-source Gmail assistant that
> runs inside an Intel TDX enclave so that the operator cannot read user mail.
> The architecture is settled enough that I would like it torn apart by people
> who do this seriously, before I write any marketing about it.
>
> Two things. First, are there two or three people you would suggest I talk to
> about the security model? I am specifically looking for someone who will tell
> me the claim is weaker than I think it is. Happy to be introduced or to reach
> out cold with your name, whichever is easier for you.
>
> Second, could you send me your Signal number? Some of what I want to ask
> about the threat model is easier there than over Gmail, for reasons that are
> slightly funny given the product.
>
> Thank you,
> Morgan

### 9b. Cold email to a security person

Six sentences maximum. Lead with the specific thing you want criticised, not
with the product.

> Hi [Name],
>
> I read your [SPECIFIC POST/TALK] on [TOPIC], and the part about [SPECIFIC
> POINT] is directly relevant to something I am building.
>
> I am building an open-source AI email assistant that runs inside an Intel TDX
> enclave, with the goal that the operator cannot read user mail and that this
> is verifiable rather than promised. The part I am least confident about is
> that inference currently runs outside the enclave on a normal EU cloud, so a
> third party sees masked text, and I do not think my masking is as good as I
> would like it to be.
>
> I am not selling anything and there is nothing to sign up for. I am wondering
> whether you would be willing to spend twenty minutes telling me where the
> claim is weaker than I think. The threat model is [LINK] and the code is
> [LINK], so you can also just reply with the problems and skip the call.
>
> Thank you,
> Morgan

### 9c. Asking for an introduction

> Hi [Name],
>
> I recognize that introductions cost you something, so no problem at all if
> this is not a good fit.
>
> I am building an open-source Gmail assistant that runs in a hardware enclave,
> and I am trying to find people who will find holes in the security model
> before I make claims about it publicly. [PERSON] came up because of
> [SPECIFIC REASON].
>
> If you think it makes sense, I have written a two-paragraph version you can
> forward without editing (below). If not, I am also happy to reach out
> directly and leave you out of it.
>
> Thank you,
> Morgan
>
> [forwardable block]

### 9d. Waitlist welcome email

> Hi [First],
>
> Thank you for signing up. Here is the threat model document: [LINK].
>
> A summary of where things actually stand. The enclave and attestation work,
> the code is public at [LINK], and the assistant already drafts replies and
> handles calendar scheduling. The weakest part is that model inference runs
> outside the enclave on an EU cloud, so one vendor sees text with identifiers
> stripped. Moving that inside is the next milestone and I will tell you when
> it lands.
>
> You will hear from me at most once a month. If you find something wrong in
> the threat model, replying to this email reaches me directly.
>
> Best,
> Morgan

---

## 10. Forum and community outreach

Where the complaints are (search these, do not spam them):

- Hacker News threads on AI email tools, Gemini in Gmail, agent permissions
- r/privacy, r/selfhosted, r/degoogle, r/ExperiencedDevs on AI tooling access
- Lobste.rs security and privacy tags
- Mastodon infosec instances (infosec.exchange)
- Proton and Tuta community forums, where the audience self-selected already
- Comments on any "Google is training on your email" news cycle

**Rules for these posts:**

- Reply to the specific thing the person said. Never paste a template.
- Disclose that you built it, in the first sentence, every time.
- Include the limitation unprompted. In these communities that is what buys
  you the right to post at all.
- Do not post more than once per thread. Do not reply to critics defensively.
- If someone finds a real hole, thank them by name and fix it publicly.

**Shape of a good reply:**

> I built something in this space, so treat this as biased. The specific thing
> you are describing (the assistant needs full mailbox access, and then that
> access sits on someone else's server) is the problem I have been working on.
> My approach is to run it in a TDX enclave so the operator cannot read the
> mailbox, and to publish the code so the attestation hash can be checked.
>
> The honest limitation is that inference is still outside the enclave right
> now, so a cloud vendor sees masked text. If that is a dealbreaker for you
> then it should be, and I would rather say so here than have you find out
> later. [LINK] if useful.

That last paragraph is the whole strategy. You are not going to out-market
anyone. You can out-honest everyone.

---

## 11. Launch site listings

For Product Hunt, BetaList, Indie Hackers, AlternativeTo, Hacker News
Show HN, awesome-selfhosted, r/SideProject.

**Tagline, 60 characters:**

> Agentic email for Gmail that the operator cannot read

**Alternates:**

> Open-source Gmail AI that runs in a hardware enclave
> AI email assistant with a hardware proof, not a privacy policy
> Your Gmail assistant, running where nobody can look in

**Short description, ~200 characters:**

> Letterlock drafts your Gmail replies, handles scheduling, and summarises your
> inbox. It runs inside an Intel TDX enclave and publishes an attestation of
> the exact open-source code it is executing.

**Show HN title:**

> Show HN: Letterlock, an open-source Gmail assistant running in a TDX enclave

Show HN body should lead with architecture, not benefits, and should include
the Scaleway limitation in the first three paragraphs. That crowd will find it
in ten minutes otherwise, and finding it themselves is much worse than being
told.

---

## 12. Daily rhythm

One build item and one outreach item per day. Outreach items in rough
increasing order of difficulty, so early days are cheap:

1. Ship the waitlist page and the threat model doc.
2. Email David. Ask for the Signal number and two or three names.
3. Write the "how infrastructure fails" post. Publish on your own domain first.
4. Show HN once the beta is real, not before.
5. One cold email per day to a security person, referencing something specific
   they wrote.
6. One forum reply per day, only where the complaint already exists.
7. List on BetaList, AlternativeTo, awesome-selfhosted, Indie Hackers.
8. Weekly build-log post. Include what broke.

Metric worth tracking: reply rate on cold emails, not signup count. At this
stage a security person who writes back with three objections is worth more
than fifty waitlist rows.

---

## 13. Open questions for you

- What is the satellite and defense employer's name, and are you comfortable
  naming it in public copy?
- Is the 20 euro price fixed, and does the founding-price offer fit your
  actual inference cost per user?
- Who is David, in one line, so the email above can be made specific?
