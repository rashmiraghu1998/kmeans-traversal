"""Secure communications primitives (wrapper).

Functions for secure communications with oneself (via secret-key
cryptography) and with others (via public-key cryptography).
"""

# Attempt to load each of the two wrappers.
comm = None
try:
    try:
        from pigg.crypto.comm_pynacl import comm_pynacl
    except:
        from crypto.comm_pynacl import comm_pynacl
    comm = comm_pynacl
except:
    try:
        try:
            from pigg.crypto.comm_cigg import comm_cigg
        except:
            from crypto.comm_cigg import comm_cigg
        comm = comm_cigg
    except:
        raise RuntimeError("could not load PyNaCl or CIGG")
