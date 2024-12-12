"""Wire label data structure.

Data structure used to represent wire labels in a
garbled circuit protocol implementation.
"""

import secrets

class LabelUsingBytes():
    """
    Class for label data structure that uses `bytearray`
    as its internal representation.
    """

    @staticmethod
    def random():
        return LabelUsingBytes(bytearray(secrets.token_bytes(LabelUsingBytes.LABEL_LENGTH)))

    @staticmethod
    def zero():
        return LabelUsingBytes(bytearray(LabelUsingBytes.LABEL_LENGTH))

    def __init__(self, bytes):
        """Initialize a label data structure instance."""
        self.bytes = bytes

    def inject(self, point):
        self.bytes[0] = self.bytes[0] & 254
        self.bytes[0] = self.bytes[0] | point

    def extract(self):
        return self.bytes[0] & 1

    def copy_deep(self):
        return LabelUsingBytes(self.bytes)

    def __getitem__(self, i):
        return self.bytes[i]

    def __xor__(self, other):
        bs = [self.bytes[i] ^ other.bytes[i] for i in range(len(self.bytes))]
        return LabelUsingBytes(bytearray(bs))

    def __eq__(self, other):
        return self.bytes == other.bytes

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str([int(b) for b in self.bytes])
