#!/usr/bin/env python3

import argparse
import datetime
import yaml
import onepif
import kpwriter

from os.path import splitext

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


# Load record mappings from Yaml file
RECORD_MAP = yaml.load(open("mappings.yml", "rt"), Loader=yaml.SafeLoader)

uuid_map = {}

for item in opif:

    props = item.get_all_props()

    # Fields that are not to be added as custom properties
    fids_done = ["passwordHistory"]

    # Determine group/folder
    item_type_name = item.type_name
    target_group_name = "{}s".format(item_type_name)   # plural for group

    if item.is_trash():
        target_group_name = "Recycle Bin"

    # Add entry to KeePass
    entry = kp.add_entry(target_group_name, props["title"])
    fids_done.append("title")

    # UUID - memorise for later linking?
    uuid_map[props["uuid"]] = entry.uuid
    fids_done.append("uuid")

    # Icon
    kp_icon = RECORD_MAP[item.type]["icon"]
    kp.set_icon(kp_icon)

    # URLs
    if "location" in props:
        kp.add_url(props["location"])
        fids_done.append("location")
        fids_done.append("locationKey")
    if "URLs" in props:
        for u in props["URLs"]:
            kp.add_url(u["url"])
        fids_done.append("URLs")
    if "URL" in props:
        kp.add_url(props["URL"])
        fids_done.append("URL")

    # Tags
    kp.set_tags(item.get_tags())
    fids_done.append("tags")

    # TOTPs
    totps = item.get_totps()
    if totps:
        for totp in totps:
            kp.add_totp(totp[0], title=totp[1])

    # Notes
    if "notesPlain" in props:
        entry.notes = props["notesPlain"]
        fids_done.append("notesPlain")

    # Dates
    entry.ctime = datetime.datetime.fromtimestamp(props["createdAt"])
    entry.mtime = datetime.datetime.fromtimestamp(props["updatedAt"])
    fids_done.append("createdAt")
    fids_done.append("updatedAt")

    # Apply mappings from mappings.yml
    for map_field in ["username", "password"]:
        seek_fields = RECORD_MAP[item.type][map_field]
        if not seek_fields:
            continue
        if type(seek_fields) is str:
            seek_fields = [seek_fields]
        for fid in seek_fields:
            if fid in props:
                setattr(entry, map_field, props[fid])
                fids_done.append(fid)
                break

    # Set remaining properties
    for k, v in props.items():
        if k in ["Password"]:
            # Forbidden name
            continue
        if k in RECORD_MAP["General"]["ignored"]:
            # Skip ignored fields
            continue
        if k in fids_done:
            # Skip fields processed elsewhere
            continue
        kp.set_prop(k, str(v))



   # TODO: scope: Never = never suggest in browser (i.e. don't add KPH fields)

    secure = item.raw["secureContents"]
    # Other web fields
    if "fields" in secure:
        for field in secure["fields"]:
            d = field.get("designation")
            if d != "username" and d != "password":
                entry.set_custom_property("KPH: {}".format(field["name"]), field["value"])

    # AFTER ALL OTHER PROCESSING IS DONE: Password history
    if "passwordHistory" in props:
        original_password = entry.password
        original_mtime = entry.mtime
        for p in props["passwordHistory"]:
            d = datetime.datetime.fromtimestamp(p["time"])
            entry.mtime = d
            entry.password = p["value"]
            entry.save_history()
        # Restore original values
        entry.password = original_password
        entry.mtime = original_mtime

kp.save()
