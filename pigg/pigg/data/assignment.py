"""Wire-to-label assignment data structure.

Data structure for mapping wires to labels in a garbled
circuit protocol implementation.
"""

try:
    from pigg.data.label import *
except:
    from pigg.pigg.data.label import *

class Assignment(list):
    """
    Data structure for representing sets of
    garbled gates and wire-to-label maps.
    """

    def keep_only(self, indices):
        return Assignment(self[i] for i in indices)

    @staticmethod
    def from_srgg(srgg):
        label_length = srgg[0]
        length = srgg[1]
        length += srgg[2] * 256
        length += srgg[3] * 65536
        length += srgg[4] * 16777216

        index = 5
        assignment = Assignment()
        for _ in range(length):
            op = srgg[index]
            entries = srgg[index + 1]
            index += 2
            labels = []
            for __ in range(entries):
                labels.append(Label.from_bytes(srgg[index:index+label_length]))
                index += label_length
            assignment.append(labels)

        return assignment

    @staticmethod
    def from_srgg_opt(srgg):
        """
        This version does not convert byte data into
        the `Label` data structure, delaying that until
        the evaluation stage.
        """
        label_length = srgg[0]
        length = srgg[1]
        length += srgg[2] * 256
        length += srgg[3] * 65536
        length += srgg[4] * 16777216

        index = 5
        assignment = Assignment()
        for _ in range(length):
            entries = srgg[index + 1]
            index += 2
            labels = None
            if entries > 0:
                labels = srgg[index:index+16*4]
                index += 16*4
            assignment.append(labels)

        return assignment

    def to_srgg(self):
        srgg = bytearray([Label.LABEL_LENGTH])
        length = len(self)
        srgg.append(length % 256)
        srgg.append((length // 256) % 256)
        srgg.append((length // 65536) % 256)
        srgg.append((length // 16777216) % 256)

        for labels in self:
            srgg.append(1)
            srgg.append(len(labels))
            for label in labels:
                srgg.extend(label.bytes())

        return srgg
