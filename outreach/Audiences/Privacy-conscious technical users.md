# Privacy-conscious technical users

**Status:** not started

Self-hosters, infosec people, the Signal-and-Tuta crowd, cryptocurrency-adjacent privacy engineers. They will understand the custody design instantly and will attack it.

## Threat model, in their words

Not "someone reads my mail" but "the vendor's business model requires reading my mail." Their instinct is that any hosted AI email tool is a data-collection scheme with a UI. Your split-custody design and the co-signer are the only answers they will accept, and the only reason they will not immediately say "I will just run a local model."

## Where they are

- [[Privacy Guides Community]] — the largest personal-privacy forum, and the one that will stress-test claims hardest
- [[Reddit]] — r/privacy, r/netsec, r/selfhosted
- [[Show HN]] and Hacker News comment threads
- [[Mastodon and Bluesky]] — infosec.exchange in particular
- [[Podcasts and YouTube]] — Surveillance Report, The New Oil
- [[Chaos Computer Club]] and [[CCC Berlin]] in person
- [[Discord and chat servers]] — the TEE ecosystem servers

## What they will ask, and what you say

**"TEEs are broken. TEE.fail, WireTap, memory-bus interposition."** True, and you say so first. The claim is not that a TEE is unbreakable; it is that breaking one requires physical access to datacentre hardware, whereas the alternative is plaintext on an ordinary server that any employee with production access can read. Defence in depth alongside encryption, open source, and a legal commitment.

**"Attested end to end?"** No. Inference runs in the provider's enclave. Your own stack is not fully attested yet. Never round this up. See `docs/LETTERLOCK SOFT-LAUNCH TO-DO`, honesty check 2.

**"Open source proves nothing about what you deploy."** Correct, and you say that too. Open source proves intent; attestation proves deployment; you have the first and part of the second.

**"Why not run a local model?"** Some of them will, and they were never customers. The honest answer is quality and battery life, not privacy.

## Warning

This group converts poorly and comments loudly. Treat it as free adversarial review of your claims, which is genuinely valuable given that the claims *are* the product. Do not measure success here in signups.

## Related

[[Audiences]] · [[Evidence]] · [[Competitors and adjacent products]]
