#!/usr/bin/env python3
"""Build libs/montoya-api-real.jar from a local Burp Suite installation.

The Montoya API on Maven Central may not match the version bundled with your
Burp, which shows up as NoSuchMethodError at runtime. Extracting the burp/api/
classes straight out of burpsuite.jar guarantees the two agree.

Usage:
    python3 scripts/extract-local-montoya.py [path/to/burpsuite.jar]

With no argument the script looks in the usual install locations for this OS.
It can be run from anywhere -- paths are resolved relative to the repo, not the
current working directory.
"""

import os
import shutil
import sys
import tempfile
import zipfile
from glob import glob

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(REPO_ROOT, "libs", "montoya-api-real.jar")

CANDIDATE_GLOBS = [
    # macOS
    "/Applications/Burp Suite*.app/Contents/Resources/app/burpsuite.jar",
    os.path.expanduser("~/Applications/Burp Suite*.app/Contents/Resources/app/burpsuite.jar"),
    # Windows
    r"C:\Program Files\BurpSuite*\burpsuite.jar",
    os.path.expanduser(r"~\AppData\Local\BurpSuite*\burpsuite.jar"),
    # Linux
    os.path.expanduser("~/BurpSuite*/burpsuite.jar"),
    "/opt/BurpSuite*/burpsuite.jar",
    "/usr/share/burpsuite/burpsuite.jar",
]


def locate_burp_jar():
    for pattern in CANDIDATE_GLOBS:
        matches = sorted(glob(pattern))
        if matches:
            return matches[-1]
    return None


def main():
    if len(sys.argv) > 1:
        burp_jar = sys.argv[1]
        if not os.path.isfile(burp_jar):
            sys.exit("Not a file: %s" % burp_jar)
    else:
        burp_jar = locate_burp_jar()
        if burp_jar is None:
            sys.exit(
                "Could not find burpsuite.jar automatically.\n"
                "Pass the path explicitly:\n"
                "    python3 scripts/extract-local-montoya.py /path/to/burpsuite.jar"
            )
        print("Found Burp: %s" % burp_jar)

    staging = tempfile.mkdtemp(prefix="montoya-")
    try:
        with zipfile.ZipFile(burp_jar) as z:
            # .class only. burpsuite.jar ships the Montoya .java sources alongside
            # the classes, and javac defaults its sourcepath to the classpath -- so
            # a jar containing both makes javac implicitly recompile the API and
            # emit burp/api/*.class into the build output, which then gets packaged
            # into the extension. Burp supplies those classes itself, so shipping a
            # second copy invites classloader trouble.
            members = [
                n for n in z.namelist()
                if n.startswith("burp/api/") and n.endswith(".class")
            ]
            if not members:
                sys.exit(
                    "No burp/api/ classes in %s -- is that really burpsuite.jar?" % burp_jar
                )
            z.extractall(staging, members)

        os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
        with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as out:
            for root, _dirs, files in os.walk(os.path.join(staging, "burp")):
                for name in files:
                    path = os.path.join(root, name)
                    # Store paths relative to the staging root so entries land at
                    # burp/api/... inside the jar.
                    out.write(path, os.path.relpath(path, staging))
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    print(
        "Wrote %s (%d classes, %.1f MB)"
        % (OUTPUT, len(members), os.path.getsize(OUTPUT) / 1024.0 / 1024.0)
    )
    print("Now run: gradle jar")


if __name__ == "__main__":
    main()
