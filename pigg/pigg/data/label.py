"""Wire label data structure.

Data structure used to represent wire labels in a
garbled circuit protocol implementation.
"""

import secrets

class Label():
    """
    Class for label data structure that uses `int`
    as its internal representation.
    """

    # Constant used across garbling/evaluation algorithms.
    LABEL_LENGTH = 16

    @staticmethod
    def random(i=None):
        return\
            Label(
                int.from_bytes(
                    bytearray(secrets.token_bytes(Label.LABEL_LENGTH)),
                    'little'
                )
            )

    @staticmethod
    def random_non_zero():
        bs = secrets.token_bytes(Label.LABEL_LENGTH)
        while all(b == 0 for b in bs):
            bs = secrets.token_bytes(Label.LABEL_LENGTH)
        return Label(int.from_bytes(bytearray(bs), 'little'))

    @staticmethod
    def deterministic(i):
        return Label(
            int.from_bytes(
                bytes(reversed(i.to_bytes(16, 'little'))), 
                'little'
            )
        )

    @staticmethod
    def zero():
        return Label(0)

    @staticmethod
    def from_bytes(bytes):
        return Label(int.from_bytes(bytes, 'little'))

    def __init__(self, data):
        """Initialize a label data structure instance."""
        self.int = data % (2**(8*Label.LABEL_LENGTH))

    def bytes(self):
        return self.int.to_bytes(Label.LABEL_LENGTH, 'little')

    def to_bytes(self):
        return self.int.to_bytes(Label.LABEL_LENGTH, 'little')

    def inject(self, point):
        self.int = self.int - (self.int % 2) + point

    def extract(self):
        return (self.int % 2) & 1

    #def __getitem__(self, i):
    #    return self.bytes()[i]

    def __xor__(self, other):
        return Label(self.int ^ other.int)

    def __eq__(self, other):
        return self.int == other.int

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str([int(b) for b in self.bytes()])
