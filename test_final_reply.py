#!/usr/bin/env python3
"""Unit tests for agentic_drafter._extract_final_reply.

No network/API — exercises only the FINAL REPLY marker parsing. Run:
    python3 test_final_reply.py
"""

import agentic_drafter as ad


def check(name, got, want):
    assert got == want, f"{name}\n--- got ---\n{got!r}\n--- want ---\n{want!r}"
    print(f"ok: {name}")


# Example 1 — reasoning before the marker is discarded.
raw1 = (
    "The sender wants Thursday afternoon or Friday morning. I checked the\n"
    "calendar: Thursday 3pm is open, Friday is fully booked. Propose Thursday.\n"
    "\n"
    "FINAL REPLY:\n"
    "Hi Alice,\n"
    "\n"
    "Thursday after 3pm works well for me. Does 3:30 at Blue Bottle suit you?\n"
    "\n"
    "Best,\n"
    "Morgan"
)
check("example1_reasoning_stripped", ad._extract_final_reply(raw1),
      "Hi Alice,\n\n"
      "Thursday after 3pm works well for me. Does 3:30 at Blue Bottle suit you?\n\n"
      "Best,\nMorgan")

# Example 2 — an inline mention of the phrase mid-sentence must NOT trigger;
# only the lone marker line counts.
raw2 = (
    "I'll keep this brief and decline politely. I won't over-explain in the\n"
    "FINAL REPLY, just a clean no with a door left open.\n"
    "\n"
    "FINAL REPLY:\n"
    "Hi Sam,\n"
    "\n"
    "Thanks for thinking of me. I can't take this on right now, but please keep\n"
    "me in mind for the next round.\n"
    "\n"
    "Morgan"
)
check("example2_inline_mention_ignored", ad._extract_final_reply(raw2),
      "Hi Sam,\n\n"
      "Thanks for thinking of me. I can't take this on right now, but please keep\n"
      "me in mind for the next round.\n\n"
      "Morgan")

# Last marker wins even when an earlier marker line appears in reasoning.
raw3 = (
    "Draft attempt: FINAL REPLY:\n"
    "Hi (rough)\n"
    "\n"
    "On reflection, tighten it.\n"
    "\n"
    "FINAL REPLY:\n"
    "Hi Jo,\n"
    "\n"
    "Sounds good, see you then.\n"
    "\n"
    "Morgan"
)
check("last_marker_wins", ad._extract_final_reply(raw3),
      "Hi Jo,\n\nSounds good, see you then.\n\nMorgan")

# No marker at all — falls back to the greeting heuristic.
raw4 = (
    "Here is my reasoning about tone.\n"
    "Hi Pat,\n"
    "\n"
    "Confirmed for Tuesday.\n"
    "\n"
    "Morgan"
)
check("fallback_to_greeting", ad._extract_final_reply(raw4),
      "Hi Pat,\n\nConfirmed for Tuesday.\n\nMorgan")

# Marker without trailing colon is still recognized.
raw5 = "thinking...\n\nFINAL REPLY\nHi Lee,\n\nYes.\n\nMorgan"
check("marker_without_colon", ad._extract_final_reply(raw5),
      "Hi Lee,\n\nYes.\n\nMorgan")

# Quoted marker line (e.g. leading '>') is still recognized.
raw6 = "reasoning\n> FINAL REPLY:\nHi Ada,\n\nDone.\n\nMorgan"
check("quoted_marker", ad._extract_final_reply(raw6),
      "Hi Ada,\n\nDone.\n\nMorgan")

# Empty / None inputs are pass-through safe.
check("empty_string", ad._extract_final_reply(""), "")
check("none_input", ad._extract_final_reply(None), None)

print("\nAll _extract_final_reply tests passed.")
