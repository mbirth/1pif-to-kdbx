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

    def set_type(self, new_type):
        if new_type not in TYPES:
            raise Exception("Unknown record type: {}".format(new_type))
        self.type = new_type
        self.type_name = TYPES[new_type]

    def get_tags(self):
        if "openContents" not in self.raw:
            return []
        if "tags" not in self.raw["openContents"]:
            return []
        return self.raw["openContents"]["tags"]

    def get_totps(self):
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

    def is_trash(self):
        if "trashed" in self.raw:
            return self.raw["trashed"]
        return False

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
