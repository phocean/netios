from distutils.core import setup

setup(
  name = "netios",
  version = "0.72",
  description = "SSH remote configuration tool",
  author = "Jean-Christophe Baptiste",
  author_email = "jc@phocean.net",
  url = "http://www.phocean.net",
  download_url = "http://www.phocean.net/tools/netios",
  package_dir = {'': 'lib'},
  packages = ['netios'],
  scripts = ["netios"],
  long_description = """ Cisco configuration tool through SSH """,
  license = "GNU GPL v2",
  platforms = "noarch"
)
