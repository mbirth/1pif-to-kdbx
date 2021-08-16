import json
from . import OnepifEntry

SEPARATOR = "***5642bee8-a5ff-11dc-8314-0800200c9a66***"


class OnepifReader():

    def __init__(self, filename):
        self.filename = filename
        self.fp = open(self.filename, "rt")

    def __iter__(self):
        return self

    def __next__(self):
        raw_entry = self.get_next_json()
        if not raw_entry:
            raise StopIteration
        obj_dict = self.parse_into_dict(raw_entry)
        op_entry = OnepifEntry.OnepifEntry(obj_dict)
        return op_entry

    def get_next_json(self):
        buffer = []
        is_eof = True
        for line in self.fp:
            is_eof = False
            if line.strip() == SEPARATOR:
                break
            buffer.append(line)
        if is_eof:
            return False
        json_str = "".join(buffer)
        return json_str

    def parse_into_dict(self, raw_entry):
        return json.loads(raw_entry)
