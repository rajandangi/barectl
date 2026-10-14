import base64
import gzip
import json
import sys

from sites.bodies.common import create

if __name__ == "__main__":
    create(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
