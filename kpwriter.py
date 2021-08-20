import pykeepass.icons
from urllib.parse import quote_plus
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

    def add_totp(self, init_string, otp_url=None):
        if not otp_url:
            otp_url = "otpauth://totp/Sample:username?secret={}&algorithm=SHA1&digits=6&period=30&issuer=Sample".format(quote_plus(init_string))
        # TODO: Support multiple / don't overwrite
        self.current_entry.set_custom_property("TimeOtp-Secret-Base32", init_string)
        self.current_entry.set_custom_property("otp", otp_url)
