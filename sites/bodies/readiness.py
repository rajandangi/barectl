import base64
import gzip
import json
import sys

from sites.bodies.common import set_site_readiness

if __name__ == "__main__":
    set_site_readiness(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
