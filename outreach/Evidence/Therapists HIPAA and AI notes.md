# Therapists HIPAA and AI notes

The therapy profession is having your argument with itself right now, in public, and mostly about note-taking tools rather than email. That conversation is directly transferable.

## What the profession is being told, 2026

- **A BAA is mandatory.** Any vendor handling PHI on a therapist's behalf is a business associate and must sign a Business Associate Agreement. Without one there is no lawful use of the tool with client data. This is stated flatly in practice-management guidance.
- **Ask in writing whether the vendor trains on client data.** Trustworthy clinical tools are expected to state explicitly that they do not train on customer PHI. The profession has been coached to demand exactly the assurance you can give architecturally.
- **The stated worry is where the data goes.** When a tool records or processes a session, the content is transmitted to company servers and stored by a private technology company. Commentary in 2026 put it plainly: a client's most sensitive disclosures end up held by a vendor, not only by the therapist.
- **2026 HIPAA changes** push encryption at rest and in transit, at NIST levels (256-bit minimum), and MFA, from addressable toward effectively mandatory for ePHI.

## What this means for Letterlock

Good news and a hard constraint, in that order.

**Good:** the buying question in this market is already "what does the vendor do with the content," and you have the best available answer. Nobody has to be educated into caring.

**Hard:** the gate is contractual. A BAA is a signed document with liability attached, not a cryptographic property. No enclave removes the requirement. Before selling to a single therapist, decide whether you will sign BAAs and what that obligates you to (breach notification timelines, subcontractor flow-down, audit rights). Not deciding is itself a decision to stay out of this market.

There is a real argument that your architecture makes a BAA *easier* to sign honestly than it is for a normal vendor, since much of a BAA's risk is employee access you have engineered away. That is an argument worth having with a lawyer before making it in public.

## Where to look next, yourself

- The private-practice Facebook groups listed in [[Therapists and counsellors]], which is where this profession actually argues
- r/therapists and r/psychotherapy, which I could not read. See [[Reddit]]
- SimplePractice and TherapyNotes blogs, which set the terms of the debate for most of the market

## Related

[[Evidence]] · [[Therapists and counsellors]] · [[Doctors and clinicians]]
