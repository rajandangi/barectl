import base64
import gzip
import json
import sys

from laravel.bodies.common import deploy

if __name__ == "__main__":
    deploy(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
