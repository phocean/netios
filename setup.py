from distutils.core import setup

setup(
  name = "netios",
  version = "0.71",
  description = "SSH remote configuration tool",
  author = "Jean-Christophe Baptiste",
  author_email = "jc@phocean.net",
  url = "http://www.phocean.net",
  package_dir = {'': 'lib'},
  packages = ['netios'],
  scripts = ["netios"],
  long_description = """ Cisco configuration tool through SSH """
)
