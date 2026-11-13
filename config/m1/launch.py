"""Drop inherited core-dump permission before executing a role's fixed command."""

import os
import resource
import sys

if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execvp(sys.argv[1], sys.argv[1:])
