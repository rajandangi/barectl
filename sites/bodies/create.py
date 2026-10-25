import base64
import gzip
import json
import sys

from sites.bodies.common import create
from sites.bodies.logrotate import logrotate_install, logrotate_present

if __name__ == "__main__":
    document = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    create(document)
    # Every log Barectl created gets the distro's rotation; a host without logrotate keeps
    # its site and reports the missing rotation (Phase C #389).
    logrotate_install(str(document["identifier"]), logrotate_present(str(document["identifier"])))
