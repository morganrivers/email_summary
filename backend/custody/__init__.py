"""Split-custody OAuth token handling (Track I of docs/plan_token_custody.md).

Three modules, one boundary each:

  wrapping.py  the enclave's own encryption layer (the *inner* one)
  client.py    the RPC to the co-signer, which holds the *outer* layer
  tokens.py    the refresh flow both of them exist to serve

No Gmail refresh token is stored in a form either box can open alone. The
enclave holds every ciphertext and cannot strip the outer wrap; the co-signer
holds the outer key and never holds a ciphertext to unwrap. Reading one
mailbox takes a live compromise of both, one request at a time.
"""
