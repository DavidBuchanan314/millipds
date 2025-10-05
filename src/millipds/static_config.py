"""
Hardcoded configs (it is not expected that end-users need to edit this file)

(some of this stuff might want to be broken out into a proper config file, eventually)
"""

HTTP_LOG_FMT = (
	'%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
)

GROUPNAME = "millipds-sock"

# this gets bumped if we make breaking changes to the db schema
MILLIPDS_DB_VERSION = 4

ATPROTO_REPO_VERSION_3 = 3  # might get bumped if the atproto spec changes
CAR_VERSION_1 = 1

DATA_DIR = "./data"
MAIN_DB_PATH = DATA_DIR + "/millipds.sqlite3"
REPOS_DIR = DATA_DIR + "/repos"

# might want to tweak this upwards on a very active PDS
FIREHOSE_QUEUE_SIZE = 100

# NB: each firehose event can be up to ~1MB, but on average they're much smaller

# Blob storage chunk size - cannot be reconfigured after database initialization
# as changing this will break existing blob storage
BLOB_PART_SIZE = 0x10000  # 64KB

DID_CACHE_TTL = 60 * 60  # 1 hour
DID_CACHE_ERROR_TTL = 60 * 5  # 5 mins

PLC_DIRECTORY_HOST = "https://plc.directory"

ACCESS_EXP = 60 * 60 * 2  # 2 h
REFRESH_EXP = 60 * 60 * 24 * 90  # 90 days
