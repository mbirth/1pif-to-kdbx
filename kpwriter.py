import json
import pykeepass.icons
from urllib.parse import quote_plus, urlparse
from pykeepass import create_database


class KpWriter:
    def __init__(self, filename, password="test"):
        self.kp = create_database(filename, password)
        self.current_entry = None

    def add_entry(self, dest_group_name, title):
        # Find group and create if not yet there
        group = self.kp.find_groups(name=dest_group_name, first=True)
        if not group:
            # TODO: Handle nested groups?
            group = self.kp.add_group(self.kp.root_group, dest_group_name)

        self.current_entry = self.kp.add_entry(group, title, "", "")
        return self.current_entry

    def save(self):
        return self.kp.save()

    def set_icon(self, icon_id):
        if icon_id in dir(pykeepass.icons):
            kp_icon_id = getattr(pykeepass.icons, icon_id)
        else:
            # FIXME: Assume kp_icon is already ID, needed b/c icon 12 is missing from pykeepass.icons
            kp_icon_id = icon_id
        self.current_entry.icon = kp_icon_id

    def set_tags(self, tag_list):
        self.current_entry.tags = tag_list

    def add_totp(self, init_string, otp_url=None, title=""):
        if not otp_url:
            otp_url = "otpauth://totp/Sample:username?secret={}&algorithm=SHA1&digits=6&period=30&issuer=Sample".format(quote_plus(init_string))

        # It's possible to define multiple OTP-secrets in 1P7, so let's not lose one
        suffix = ""
        suffix_ctr = 1
        while self.current_entry.get_custom_property("otp{}".format(suffix)):
            suffix_ctr += 1
            suffix = "_{}".format(suffix_ctr)

        self.set_prop("TimeOtp-Secret-Base32{}".format(suffix), init_string, True)
        self.set_prop("otp{}".format(suffix), otp_url)
        if len(title) > 0:
            self.set_prop("otp_title{}".format(suffix), title)

    def add_url(self, url):
        if not self.current_entry.url:
            self.current_entry.url = url
        else:
            # https://github.com/keepassxreboot/keepassxc/pull/3558
            suffix = ""
            suffix_ctr = 0
            while self.current_entry.get_custom_property("KP2A_URL{}".format(suffix)):
                suffix_ctr += 1
                suffix = "_{}".format(suffix_ctr)
            self.set_prop("KP2A_URL{}".format(suffix), url)

        # KeePassHttp
        current_settings = self.current_entry.get_custom_property("KeePassHttp Settings")
        if current_settings:
            current_settings = json.loads(current_settings)
        else:
            current_settings = {
                "Allow": [],
                "Deny": [],
                "Realm": "",
            }
        parsed_url = urlparse(url)
        current_settings["Allow"].append(parsed_url.hostname)
        current_settings["Allow"] = list(set(current_settings["Allow"]))
        self.set_prop("KeePassHttp Settings", json.dumps(current_settings))

    def set_prop(self, key, value, protected=False):
        self.current_entry.set_custom_property(key, value)
        if protected:
            # https://github.com/libkeepass/pykeepass/issues/89
            self.current_entry._element.xpath('String[Key[text()="{}"]]/Value'.format(key))[0].attrib["Protected"] = "True"
