import sys
from datetime import datetime

TYPES = {
    "112": "API Credential",
    "wallet.financial.BankAccountUS": "Bank Account",
    "wallet.financial.CreditCard": "Credit Card",
    "wallet.computer.Database": "Database",
    # Not exported: Document
    "wallet.government.DriversLicense": "Driver License",
    "wallet.onlineservices.Email.v2": "Email Account",
    "identities.Identity": "Identity",
    "webforms.WebForm": "Login",
    "113": "Medical Record",
    "wallet.membership.Membership": "Membership",
    "wallet.government.HuntingLicense": "Outdoor License",
    "wallet.government.Passport": "Passport",
    "passwords.Password": "Password",
    "wallet.membership.RewardProgram": "Reward Program",
    "securenotes.SecureNote": "Secure Note",
    "wallet.computer.UnixServer": "Server",
    "wallet.government.SsnUS": "Social Security Number",
    "wallet.computer.License": "Software License",
    "wallet.computer.Router": "Wireless Router",
}


class OnepifEntry():

    def __init__(self, data):
        self.raw = data
        self.set_type(data["typeName"])

    def set_type(self, new_type: str):
        if new_type not in TYPES:
            raise Exception("Unknown record type: {}".format(new_type))
        self.type = new_type
        self.type_name = TYPES[new_type]

    def get_tags(self) -> list:
        if "openContents" not in self.raw:
            return []
        if "tags" not in self.raw["openContents"]:
            return []
        return self.raw["openContents"]["tags"]

    def get_totps(self) -> list:
        totp_fields = []
        if "sections" in self.raw["secureContents"]:
            for section in self.raw["secureContents"]["sections"]:
                if "fields" not in section:
                    continue
                for field in section["fields"]:
                    if field["n"][:5] == "TOTP_":
                        totp_fields.append([
                            field["v"],
                            field["t"],   # Custom title, if set (isn't displayed in 1P)
                        ])
        if len(totp_fields) == 0:
            return None
        return totp_fields

    def is_trash(self) -> bool:
        if "trashed" in self.raw:
            return self.raw["trashed"]
        return False

    def add_with_unique_key(self, prop_dict: dict, new_key: str, new_value):
        suffix_ctr = 0
        tmp_key = new_key
        while tmp_key in prop_dict:
            suffix_ctr += 1
            tmp_key = "{}_{}".format(new_key, suffix_ctr)
        prop_dict[tmp_key] = new_value

    def convert_section_field_to_string(self, field_data: dict) -> str:
        kind = field_data["k"]
        if kind in ["string", "concealed", "email", "phone", "URL", "menu", "cctype"]:
            return field_data["v"]
        elif kind == "date":
            return datetime.fromtimestamp(field_data["v"]).strftime("%Y-%m-%d")
        elif kind == "monthYear":
            month = field_data["v"] % 100
            month_name = datetime.strptime(str(month), "%m").strftime("%b")
            year = field_data["v"] // 100
            return "{} {}".format(month_name, year)
        elif kind == "address":
            addr = field_data["v"]
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
            return result.strip()
        elif kind == "reference":
            print("WARNING: Links between items are not supported (entry: {} -> {}).".format(self.raw["title"], field_data["t"]), file=sys.stderr)
            return field_data["t"]

        raise Exception("Unknown data kind in section fields: {}".format(kind))
        return field_data["v"]

    def parse_section_into_dict(self, target_dict: dict, section: dict):
        sect_title = section["title"]
        for f in section["fields"]:
            if "v" not in f:
                # Skip fields without data
                continue
            propname = "{}: {}".format(sect_title, f["t"].title())
            if not sect_title:
                propname = f["t"]
            propval = self.convert_section_field_to_string(f)
            self.add_with_unique_key(target_dict, propname, propval)

    def parse_fields_into_dict(self, target_dict: dict, fields: list):
        for f in fields:
            if f["type"] in ["C", "R"]:
                # Skip unsupported fields
                print("Ignoring checkbox/radiobuttons value in entry {}.".format(self.raw["title"]), file=sys.stderr)
                continue
            if "value" not in f:
                # Skip fields without data
                continue
            if "designation" in f:
                propname = f["designation"]
            else:
                propname = f["name"]
            propval = f["value"]
            if type(propval) is str:
                # For some reason 1P sometimes exports 0x10 character for empty strings
                propval = propval.replace("\x10", "")
            if f["type"] not in ["T", "P", "E"]:
                raise Exception("Unknown field type discovered: {}".format(f["type"]))
            self.add_with_unique_key(target_dict, propname, propval)

    def get_all_props(self) -> dict:
        props = {}
        for k, v in self.raw.items():
            if k in ["openContents", "secureContents"]:
                # handle open/secure groups of properties
                for k2, v2 in v.items():
                    if k2 == "unknown_details":
                        # special handling aka. black magic
                        if "sections" in v2:
                            k2 = "sections"
                            v2 = v2["sections"]
                    if k2 == "sections":
                        # handle section
                        for s in v2:
                            if "fields" not in s:
                                # Skip empty sections
                                continue
                            self.parse_section_into_dict(props, s)
                        continue
                    elif k2 == "fields":
                        # For some reason this differs from the "fields" in a section
                        self.parse_fields_into_dict(props, v2)
                        continue
                    new_key2 = k2
                    suffix_ctr2 = 0
                    while new_key2 in props:
                        suffix_ctr2 += 1
                        new_key2 = "{}_{}".format(k2, suffix_ctr2)
                    if type(v2) is str:
                        # For some reason 1P sometimes exports 0x10 character for empty strings
                        v2 = v2.replace("\x10", "")
                    props[new_key2] = v2
                continue
            new_key = k
            suffix_ctr = 0
            while new_key in props:
                suffix_ctr += 1
                new_key = "{}_{}".format(k, suffix_ctr)
            if type(v) is str:
                # For some reason 1P sometimes exports 0x10 character for empty strings
                v = v.replace("\x10", "")
            props[new_key] = v
        # TODO: Maybe walk all keys and see if there's (xxx_dd), xxx_mm, xxx_yy and turn them into a date
        return props

    def __getattr__(self, name):
        if name not in self.raw:
            raise AttributeError
        return self.raw[name]

    def __getitem__(self, key):
        if self.__missing__(key):
            raise KeyError
        return self.raw[key]

    def __contains__(self, item):
        return item in self.raw

    def __missing__(self, key):
        return key not in self.raw

    def get(self, key):
        if key not in self.raw:
            return None
        return self.raw[key]
