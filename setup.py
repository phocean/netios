# -*- coding: utf-8 -*-
from distutils.core import setup

setup(
  name = "netios",
  version = "0.74",
  description = "SSH remote configuration tool",
  author = "Jean-Christophe Baptiste",
  author_email = "jc@phocean.net",
  url = "http://www.phocean.net",
  download_url = "http://www.phocean.net/tools/netios",
  package_dir = {'': 'lib'},
  packages = ['netios'],
  scripts = ["netios"],
  long_description = """ Netios is a little tool operating Cisco routers within SSH. """,
  license = "GNU GPL v2",
  platforms = "noarch"
)
