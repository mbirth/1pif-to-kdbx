import json

SEPARATOR = "***5642bee8-a5ff-11dc-8314-0800200c9a66***"


class OnepifReader():

    def __init__(self, filename):
        self.filename = filename
        self.fp = open(self.filename, "rt")

    def __iter__(self):
        return self

    def __next__(self):
        buffer = []
        is_eof = True
        for line in self.fp:
            is_eof = False
            if line.strip() == SEPARATOR:
                break
            buffer.append(line)
        if is_eof:
            raise StopIteration
        jsonstr = "".join(buffer)
        return json.loads(jsonstr)