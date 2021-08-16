#!/usr/bin/env python3

from pykeepass import PyKeePass

kp = PyKeePass("out.kdbx", password="test")
kp.dump_xml("out.xml")
