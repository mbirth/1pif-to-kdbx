#!/usr/bin/env python3

import argparse
import datetime
import json
import onepif
import kpwriter
import pykeepass.icons

from os.path import splitext
from urllib.parse import urlparse, quote_plus

parser = argparse.ArgumentParser(description="Convert 1Password 1PIF exports into a KeePass KDBX file.")
parser.add_argument("inpath", metavar="input.1pif", help="1Password export file/folder")
parser.add_argument("outfile", metavar="output.kdbx", nargs="?", help="Desired filename for KeePass file. If omitted, defaults to <input>.kdbx. Existing files WILL BE OVERWRITTEN!")

args = parser.parse_args()

# If no outfile given, use infile name
if not args.outfile:
    fileparts = splitext(args.inpath)
    args.outfile = "{}.kdbx".format(fileparts[0])

# If given outfile doesn't have .kdbx extension, add it
outparts = splitext(args.outfile)
if outparts[1] != ".kdbx":
    args.outfile += ".kdbx"

# Open input file
print("Input file: {}".format(args.inpath))
opif = onepif.OnepifReader("{}/data.1pif".format(args.inpath))

# Open output file
print("Output file: {}".format(args.outfile))
kp = kpwriter.KpWriter(args.outfile, "test")


def getField(item, designation):
    secure = item["secureContents"]
    if "fields" in secure:
        for field in secure["fields"]:
            d = field.get("designation")
            if d == designation:
                return field["value"]

    return None


ICON_MAP = {
    "112": "GEAR",   # API Credential
    "wallet.financial.BankAccountUS": "DOLLAR_SIGN",   # Bank Account
    "wallet.financial.CreditCard": "DOLLAR_SIGN",   # Credit Card
    "wallet.computer.Database": "SERVER",   # Database
    # Not exported: Document
    "wallet.government.DriversLicense": "BUSINESS_CARD",   # Driver License
    "wallet.onlineservices.Email.v2": "ENVELOPE",   # Email Account
    "identities.Identity": "BUSINESS_CARD",   # Identity
    "webforms.WebForm": "MANAGER",   # Login
    "113": "WARNING_SIGN",   # Medical Record
    "wallet.membership.Membership": "BUSINESS_CARD",   # Membership
    "wallet.government.HuntingLicense": "BUSINESS_CARD",   # Outdoor License
    "wallet.government.Passport": "BUSINESS_CARD",   # Passport
    "passwords.Password": "KEY",   # Password
    "wallet.membership.RewardProgram": "PERCENT_SIGN",   # Reward Program
    "securenotes.SecureNote": "POST_IT",   # Secure Note
    "wallet.computer.UnixServer": "SERVER_2",   # Server
    "wallet.government.SsnUS": "BUSINESS_CARD",   # Social Security Number
    "wallet.computer.License": "CARDBOARD",   # Software License
    "wallet.computer.Router": "12",   # Wireless Router
}

for item in opif:

    # Determine group/folder
    item_type_name = item.type_name
    target_group_name = "{}s".format(item_type_name)   # plural for group

    if item.is_trash():
        target_group_name = "Recycle Bin"

    # Add entry to KeePass
    entry = kp.add_entry(target_group_name, item["title"])

    # Icon
    kp_icon = ICON_MAP[item.type]
    kp.set_icon(kp_icon)

    # Tags
    kp.set_tags(item.get_tags())

    # TOTP
    totps = item.get_totps()
    if totps:
        for totp in totps:
            kp.add_totp(totp[0], title=totp[1])




    secure = item["secureContents"]

    # Username
    if "username" in secure:
        entry.username = secure["username"]
    else:
        username = getField(item, "username")
        if username:
            entry.username = username

    # Password
    if "password" in secure:
        entry.password = secure["password"]
    else:
        new_password = getField(item, "password")
        if new_password:
            entry.password = new_password


    # Other web fields
    if "fields" in secure:
        for field in secure["fields"]:
            d = field.get("designation")
            if d != "username" and d != "password":
                entry.set_custom_property("Web field: {}".format(field["name"]), field["value"])

    # Password history
    if "passwordHistory" in secure:
        for p in secure["passwordHistory"]:
            d = datetime.datetime.fromtimestamp(p["time"])
            entry.set_custom_property("Password history ({})".format(d), p["value"])

    # Find URL in fields
    if not entry.url:
        if "htmlAction" in secure:
            entry.url = secure["htmlAction"]

    # Membership fields
    if "membership_no" in secure and not entry.username:
        entry.username = secure["membership_no"]

    # Passport fields
    if "number" in secure and not entry.username:
        entry.username = secure["number"]

    # Router fields
    if "network_name" in secure and not entry.username:
        entry.username = secure["network_name"]
    if "wireless_password" in secure and not entry.password:
        entry.password = secure["wireless_password"]

    # Bank account
    if "iban" in secure and not entry.username:
        entry.username = secure["iban"]
    if "swift" in secure and not entry.username:
        entry.username = secure["swift"]
    if "routingNo" in secure and not entry.username:
        entry.username = secure["routingNo"]
    if "accountNo" in secure and not entry.username:
        entry.username = secure["accountNo"]
    if "telephonePin" in secure and not entry.password:
        entry.password = secure["telephonePin"]

    # Credit card
    if "ccnum" in secure and not entry.username:
        entry.username = secure["ccnum"]
    if "pin" in secure and not entry.password:
        entry.password = secure["pin"]

    # Sections
    if "sections" in secure:
        for s in secure["sections"]:
            t = s["title"]
            if "fields" in s:
                for f in s["fields"]:
                    v = f.get("v")
                    if not v:
                        continue
                    k = f["k"]
                    ft = "{} - {}".format(t, f["t"])
                    if t == "":
                        ft = f["t"]
                    if ft == "URL":
                        # Reserved!
                        ft = "URL_"
                    if k in ["string", "concealed", "menu", "cctype", "monthYear", "email"]:
                        entry.set_custom_property(ft, str(v))
                    elif k == "date":
                        d = datetime.datetime.fromtimestamp(v)
                        entry.set_custom_property(ft, str(d))
                    elif k == "address":
                        # needs special handling!
                        pass   # for now
                    else:
                        raise Exception("Unknown k: {}".format(k))

    # Notes
    if "notesPlain" in secure:
        entry.notes = secure["notesPlain"]

    # URLs
    settings = {
        "Allow": [],
        "Deny": [],
        "Realm": "",
    }
    applySettings = False

    if "location" in item:
        entry.url = item["location"]
    if "URLs" in secure:
        kp2idx = 0
        for u in secure["URLs"]:
            if not entry.url:
                entry.url = u["url"]
            else:
                # https://github.com/keepassxreboot/keepassxc/pull/3558
                prop_name = "KP2A_URL"
                if kp2idx > 0:
                    prop_name += "_{}".format(kp2idx)
                entry.set_custom_property(prop_name, u["url"])
                kp2idx += 1
            url = urlparse(u["url"])
            settings["Allow"].append(url.hostname)
            applySettings = True

    if applySettings:
        settings["Allow"] = list(set(settings["Allow"]))
        entry.set_custom_property("KeePassHttp Settings", json.dumps(settings))

    # Dates
    entry.ctime = datetime.datetime.fromtimestamp(item["createdAt"])
    entry.mtime = datetime.datetime.fromtimestamp(item["updatedAt"])

kp.save()
