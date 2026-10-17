"""Repository-root launcher for the optional landscaping demonstration."""

import sys

# Do not leave Python-generated state beside the shipped example files.
sys.dont_write_bytecode = True


if __name__ == "__main__":
    from landscape.launcher import main

    main()
