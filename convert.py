#!/usr/bin/env python3

import argparse
import datetime
import json
import onepif

from os.path import splitext
from pykeepass import create_database
from urllib.parse import urlparse, quote_plus

parser = argparse.ArgumentParser(description="Convert 1Password 1PIF exports into a KeePass KDBX file.")
parser.add_argument("inpath", metavar="input.1pif", help="1Password export file/folder")
parser.add_argument("outfile", metavar="output.kdbx", nargs="?", help="Desired filename for KeePass file. If omitted, defaults to <input>.kdbx. Existing files WILL BE OVERWRITTEN!")

args = parser.parse_args()

if not args.outfile:
    fileparts = splitext(args.inpath)
    args.outfile = "{}.kdbx".format(fileparts[0])

outparts = splitext(args.outfile)
if not outparts[1] == "kdbx":
    args.outfile += ".kdbx"

kp = create_database(args.outfile, password="test")

groupLabels = {
    "passwords.Password": "Passwords",
    "webforms.WebForm": "Logins",
    "wallet.membership.Membership": "Memberships",
    "securenotes.SecureNote": "Notes",
    "wallet.government.Passport": "Passports",
    "wallet.computer.UnixServer": "Servers",
    "wallet.computer.Router": "Routers",
    "wallet.financial.BankAccountUS": "Bank Accounts",
    "wallet.financial.CreditCard": "Credit Cards",
    "wallet.computer.License": "Licenses",
}
groups = {}


def getGroup(item):
    group = groups.get(item["typeName"])
    if group:
        return group

    label = groupLabels.get(item["typeName"])
    if not label:
        raise Exception("Unknown type name {}".format(item["typeName"]))

    group = kp.add_group(kp.root_group, label)
    groups[item["typeName"]] = group
    return group


def getField(item, designation):
    secure = item["secureContents"]
    if "fields" in secure:
        for field in secure["fields"]:
            d = field.get("designation")
            if d == designation:
                return field["value"]

    return None


def getTotp(item):
    secure = item["secureContents"]
    if "sections" in secure:
        for section in secure["sections"]:
            if not "fields" in section:
                continue
            for field in section["fields"]:
                if field["t"] == "totp":
                    return field["v"]
    return None


opif = onepif.OnepifReader("{}/data.1pif".format(args.inpath))

for item in opif:
    if item.get("trashed"):
        continue

    group = getGroup(item)

    entry = kp.add_entry(group, item["title"], "", "")
    secure = item["secureContents"]

    # Tags
    if "openContents" in item and "tags" in item["openContents"]:
        entry.tags = item["openContents"]["tags"]

    # Username
    if "username" in secure:
        entry.username = secure["username"]
    else:
        entry.username = getField(item, "username")

    # Password
    if "password" in secure:
        entry.password = secure["password"]
    else:
        new_password = getField(item, "password")
        if new_password:
            entry.password = new_password

    # TOTP
    totp = getTotp(item)
    if totp:
        entry.set_custom_property("TimeOtp-Secret-Base32", totp)
        entry.set_custom_property("otp", "otpauth://totp/Sample:username?secret={}&algorithm=SHA1&digits=6&period=30&issuer=Sample".format(quote_plus(totp)))

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
                    if k == "string" or k == "concealed" or k == "menu" or k == "cctype" or k == "monthYear":
                        entry.set_custom_property(ft, str(v))
                    elif k == "date":
                        d = datetime.datetime.fromtimestamp(v)
                        entry.set_custom_property(ft, str(d))
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
