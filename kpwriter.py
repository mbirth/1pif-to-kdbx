from pykeepass import create_database


class KpWriter:
    def __init__(self, filename, password="test"):
        self.kp = create_database(filename, password)
