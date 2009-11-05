from distutils.core import setup

# files = ["things/*"]

setup(name = "netios",
  version = "0.60",
  description = "SSH remote configuration tool",
  author = "Jean-Christophe Baptiste",
  author_email = "jc@phocean.net",
  url = "http://www.phocean.net",
  packages = ['package'],
  # package_data = {'package' : files },
  scripts = ["netios"],
  long_description = """ SSH configuration tool, with functions like mass password edition """
)
