from pykeepass import create_database


class KpWriter:
    def __init__(self, filename, password="test"):
        self.kp = create_database(filename, password)
        self.last_entry = None

    def add_entry(self, dest_group_name, title):
        # Find group and create if not yet there
        group = self.kp.find_groups(name=dest_group_name, first=True)
        if not group:
            # TODO: Handle nested groups?
            group = self.kp.add_group(self.kp.root_group, dest_group_name)

        self.last_entry = self.kp.add_entry(group, title, "", "")
        return self.last_entry

    def save(self):
        return self.kp.save()
