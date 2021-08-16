class OnepifEntry():

    def __init__(self, data):
        self.raw = data

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
