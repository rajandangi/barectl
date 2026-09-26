"""The SSH alias rule shared by the Server model and the SSH configuration adapter."""

import re

# Aliases are later passed to the SSH backend as host names. Refuse anything that could be
# read as an option or needs quoting.
ALIAS = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9._-]*\Z")
ALIAS_MAX_LENGTH = 253
