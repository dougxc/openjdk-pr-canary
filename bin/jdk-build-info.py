#!/usr/bin/env python3

import argparse
import json
import urllib.request

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def get_builds():
    with urllib.request.urlopen("https://raw.githubusercontent.com/dougxc/openjdk-pr-canary/refs/heads/master/.github/scripts/builds.json") as response:
        return json.loads(response.read())

def main():
    parser = argparse.ArgumentParser(description="Show info for JDK build(s) matching a given key.")
    parser.add_argument("key", nargs="+", help="a build id or git revision used in a build")
    args = parser.parse_args()

    matches = []
    for key in args.key:
        key_is_revision = is_hex(key)

        for build in get_builds():
            if key_is_revision:
                if any((key == value) for value in build["revisions"].values()):
                    matches.append(build)
            elif key == build["id"] or key in build.get("aliases", []):
                matches.append(build)
    
    if matches:
        print(json.dumps(matches, indent=2))

if __name__ == "__main__":
    main()