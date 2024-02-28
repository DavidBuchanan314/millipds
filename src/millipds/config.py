"""
Hardcoded configs

(some of this stuff might want to be broken out into a proper config file, eventually)
"""

LOG_FMT = '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'

GROUPNAME = "millipds-sock"

DATA_DIR = "./data/"
MAIN_DB_PATH = DATA_DIR + "millipds.sqlite3"
REPOS_DIR = DATA_DIR + "repos/"
