import base64
import gzip
import json
import sys

from laravel.bodies.common import roll_back

if __name__ == "__main__":
    roll_back(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
