import sys
from datetime import datetime


class OnepifEntryProperty():

    def __init__(self, name, raw_value):
        self.name = name   # internal name
        self.title = name  # user visible name
        self.raw = raw_value
        self.set_value(raw_value)

        self.section = None
        self.type = ""
        self.web_field_name = None   # designation
        self.is_web_field = False    # has web_field_name
        self.is_protected = False

    def __repr__(self):
        return "<OnepifEntryProperty \"{}\" ({}) = {}>".format(self.name, self.title, repr(self.raw))

    def set_value(self, new_value):
        if new_value == "\x10":
            self.value = ""
        else:
            self.value = str(new_value)

    @classmethod
    def from_sectionfield(cls, field_dict: dict, sect_title: str = None):
        key = field_dict["t"]
        if not key:
            key = field_dict["n"]
        p = cls(key, field_dict)
        if sect_title:
            p.section = sect_title
            p.title = "{}: {}".format(sect_title, field_dict["t"].title())
            p.name = "{}_{}".format(sect_title.lower(), field_dict["t"].lower())

        kind = field_dict["k"]
        if kind in ["string", "email", "phone", "URL", "menu", "cctype"]:
            p.set_value(field_dict["v"])
        elif kind == "concealed":
            p.set_value(field_dict["v"])
            p.is_protected = True
        elif kind == "date":
            p.set_value(datetime.fromtimestamp(field_dict["v"]).strftime("%Y-%m-%d"))
        elif kind == "monthYear":
            month = field_dict["v"] % 100
            month_name = datetime.strptime(str(month), "%m").strftime("%b")
            year = field_dict["v"] // 100
            p.set_value("{} {}".format(month_name, year))
        elif kind == "address":
            addr = field_dict["v"]
            result = ""
            if addr["street"]:
                result += addr["street"] + "\n"
            if addr["city"]:
                result += addr["city"] + "\n"
            if addr["zip"]:
                result += addr["zip"] + "\n"
            if addr["state"]:
                result += addr["state"] + "\n"
            if addr["region"]:
                result += addr["region"] + "\n"
            if addr["country"]:
                result += addr["country"].upper()
            p.set_value(result.strip())
        elif kind == "reference":
            print("WARNING: Links between items are not supported (-> {}).".format(field_dict["t"]), file=sys.stderr)
            p.set_value(field_dict["t"])
        else:
            raise Exception("Unknown data kind in section fields: {}".format(kind))

        return p

    @classmethod
    def from_webfield(cls, field_dict: dict):
        if field_dict["type"] in ["C", "R"]:
            # Skip unsupported fields
            print("WARNING: Ignoring checkbox/radiobuttons value in entry.".format(), file=sys.stderr)
            return None
        if "value" not in field_dict or not field_dict["value"]:
            # Skip fields without data
            return None
        if "designation" in field_dict and field_dict["designation"]:
            key = field_dict["designation"]
        else:
            key = field_dict["name"]
        p = cls(key, field_dict)
        p.is_web_field = True
        if "id" in field_dict:
            p.web_field_name = field_dict["id"]
        p.set_value(field_dict["value"])
        if field_dict["type"] not in ["T", "P", "E"]:
            raise Exception("Unknown field type discovered: {}".format(field_dict["type"]))
        return p
