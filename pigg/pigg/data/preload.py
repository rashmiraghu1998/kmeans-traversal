"""Preloading embedded circuits.

This module is imported in order to preload
a collection of embedded circuits in a merged
module.
"""

try:
    from pigg.data.circuits import *
except:
    from data.circuits import *

# Circuits to load when merged module is loaded.
for circuit_name in [
        "aes-128-ecb-encrypt", "aes-128-ecb-decrypt",
        "sha-256-for-lteq-440-bits", "sha-256-for-lteq-952-bits"
    ]:
    circuits.load(circuit_name)
