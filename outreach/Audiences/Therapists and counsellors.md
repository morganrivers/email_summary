# Therapists and counsellors

**Status:** not started

Private-practice therapists. Small businesses run by one person who is also the receptionist, biller and marketer, and who is legally responsible for the most sensitive category of personal data there is.

## Threat model, in their words

HIPAA, and specifically the **Business Associate Agreement**. Any vendor that handles PHI on a therapist's behalf is a business associate and must sign a BAA; without one there is no lawful use of the tool with client data. This is a contractual gate, not a cryptographic one, and it is worth knowing that no amount of enclave engineering substitutes for a signed BAA. That is a real constraint on entering this market, not a detail.

Second concern, well documented in 2026: AI tools that record or process sessions transmit content to company servers, and therapists are being told to ask in writing whether the vendor trains on client data. The market has been primed to ask exactly the question you can answer well.

Third, 2026 HIPAA changes push encryption at rest and in transit and MFA from "addressable" toward effectively mandatory, at NIST levels. Regulatory tailwind.

## The pain that is not privacy

Client emails between sessions: rescheduling, insurance, intake, boundary-testing messages that must be answered carefully. Unpaid admin time.

## Where they are

- **Facebook groups**, which is genuinely where this profession organises: Therapists in Private Practice (TIPP), The Private Practice Startup, All Things Private Practice, Mental Health Business Development Group. Most are closed and moderated, and most ban vendor promotion outright, so join as yourself and read for weeks before saying anything
- [[Reddit]] — r/therapists, r/psychotherapy (unverified, see caveat)
- **Belongly** — belongly.com, therapist-only network
- **SimplePractice** and **TherapyNotes** blogs and communities — the practice-management incumbents; also potential partners and potential competitors
- LinkedIn groups: Mental Health Professionals Network, Private Practice Success

## Warning

Do not touch this audience with a live product until you know whether you are willing to sign BAAs and what that obligates. Talking to them for research is fine and welcome; selling without a BAA is not.

## Related

[[Audiences]] · [[Therapists HIPAA and AI notes]] · [[Doctors and clinicians]]
