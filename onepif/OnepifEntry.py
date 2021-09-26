import sys
from . import OnepifEntryProperty as oep

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

ANSI_RED = u"\u001b[1;31m"
ANSI_RESET = u"\u001b[0m"

class OnepifEntry():

    def __init__(self, data):
        self.raw = data
        self.set_type(data["typeName"])
        self.properties = []
        self.parse()

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

    def add_property(self, property: oep.OnepifEntryProperty):
        self.properties.append(property)

    def get_property_keys(self):
        keys = []
        for p in self.properties:
            keys.append(p.name)
        keys = list(set(keys))
        return keys

    def get_property(self, key: str):
        props = []
        for p in self.properties:
            if p.name == key:
                props.append(p)
        if not props:
            return None
        elif len(props) > 1:
            print("{}Warning: Multiple properties matching '{}' found: {}. Ignoring all but the first.{}".format(ANSI_RED, key, repr(props), ANSI_RESET))
        return props[0]

    def add_with_unique_key(self, prop_dict: dict, new_key: str, new_value):
        suffix_ctr = 0
        tmp_key = new_key
        while tmp_key in prop_dict:
            suffix_ctr += 1
            tmp_key = "{}_{}".format(new_key, suffix_ctr)
        if type(new_value) is str:
            # For some reason 1P sometimes exports 0x10 character for empty strings
            new_value = new_value.replace("\x10", "")
        prop_dict[tmp_key] = new_value

    def parse_section(self, section: dict):
        sect_title = section["title"]
        for f in section["fields"]:
            if "v" not in f:
                # Skip fields without data
                continue
            prop = oep.OnepifEntryProperty.from_sectionfield(f, sect_title)
            self.add_property(prop)

    def parse_fields(self, fields: list):
        for f in fields:
            prop = oep.OnepifEntryProperty.from_webfield(f)
            if prop:
                self.add_property(prop)

    def add_simple_prop(self, key: str, value):
        if value == "\x10":
            # this seems to be an "empty" indicator, so skip this
            return False
        prop = oep.OnepifEntryProperty(key, value)
        self.add_property(prop)

    def parse(self):
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
                            self.parse_section(s)
                        continue
                    elif k2 == "fields":
                        # For some reason this differs from the "fields" in a section
                        self.parse_fields(v2)
                        continue
                    # Handle all other values (most probably string or int)
                    self.add_simple_prop(k2, v2)
                continue
            # Handle all other values
            self.add_simple_prop(k, v)
        # TODO: Maybe walk all keys and see if there's (xxx_dd), xxx_mm, xxx_yy and turn them into a date
