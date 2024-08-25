#
# Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.  Oracle designates this
# particular file as subject to the "Classpath" exception as provided
# by Oracle in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
# or visit www.oracle.com if you need additional information or have any
# questions.
#

import json
import os
import subprocess
import shlex
import shutil
import zipfile
import tarfile
import glob
from argparse import ArgumentParser
from pathlib import Path

_gh_api_headers = ["-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]
_verbose = False
_repo_root = Path(subprocess.run("git rev-parse --show-toplevel".split(), capture_output=True, text=True, check=True).stdout.strip())

def gh_api(args, stdout=None, raw=False):
    cmd = ["gh", "api"] + _gh_api_headers + args
    quoted_cmd = ' '.join(map(shlex.quote, cmd))
    if stdout:
        quoted_cmd += f" >{stdout.name}"
    if _verbose:
      print(quoted_cmd)
    text = stdout is None or 'b' not in stdout.mode
    p = subprocess.run(cmd, text=text, capture_output=stdout is None, check=False, stdout=stdout)
    if p.returncode != 0:
        raise SystemExit(f"Command returned {p.returncode}: {quoted_cmd}{os.linesep}Stdout: {p.stdout}{os.linesep}Stderr: {p.stderr}")
    if raw or stdout:
        return p.stdout
    return json.loads(p.stdout)

def git(args):
    """
    Runs a git command
    """
    cmd = ["git", "-C", str(_repo_root)] + args
    if _verbose:
        quoted_cmd = ' '.join(map(shlex.quote, cmd))
        print(quoted_cmd)
    subprocess.run(cmd, check=True)

def check_bundle_naming_assumptions():
    """
    Checks bundle naming assumptions.
    """
    expect = """
    - name: 'Upload bundles artifact'
      uses: actions/upload-artifact@v4
      with:
        name: bundles-${{ inputs.platform }}${{ inputs.debug-suffix }}
        path: bundles
"""
    action_yml_path = ".github/actions/upload-bundles/action.yml"
    action_yml = gh_api(["-H", "Accept: application/vnd.github.raw", f"/repos/openjdk/jdk/contents/{action_yml_path}"], raw=True)
    assert expect in action_yml, f"""
Did not find text below in https://github.com/openjdk/jdk/blob/master/{action_yml_path} which means this script
(i.e. {Path(__file__).relative_to(_repo_root)}) needs to adapt to any bundle naming scheme change and update
the `expect` variable accordingly:

        {expect}
"""

def main():
    parser = ArgumentParser()
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose mode")
    
    args = parser.parse_args()

    global _verbose
    _verbose = args.verbose

    check_bundle_naming_assumptions()

    # Paths of written log files
    log_paths = []

    # URL for the current GitHub Action workflow run
    run_url = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}"

    # Pull requests for which libgraal building or testing failed
    failed_pull_requests = []

    prs = gh_api(["/repos/openjdk/jdk/pulls?state=open"])
    for pr in prs:
        # Ignore pull requests in draft state
        if pr["draft"] is True:
            continue

        repo = pr["head"]["repo"]["full_name"]
        head_sha = pr["head"]["sha"]

        print(f"pull request: {pr['html_url']} ({head_sha})")

        # Skip testing if the head commit has already been tested
        log_path = Path("logs").joinpath(repo, f"{head_sha}.json")
        if log_path.exists():
            print(f"{log_path} exists - skipping")
            continue

        log = {}

        # Get workflow runs for head commit in pull request
        runs = gh_api([f"/repos/{repo}/actions/runs?head_sha={head_sha}"])

        # Search runs for non-expired "bundles-linux-x64" artifact
        for run in runs["workflow_runs"]:
            run_id = run["id"]
            artifacts_obj = gh_api(["--paginate", f"/repos/{repo}/actions/runs/{run_id}/artifacts?name=bundles-linux-x64"])
            for artifact in artifacts_obj["artifacts"]:
                if artifact["expired"]:
                    print(f"{artifact['name']} expired")
                    continue
            
                artifact_id = artifact["id"]
                artifact_log = log.setdefault(f"artifact_{artifact_id}", {})

                # Download artifact
                archive = Path(f"jdk_{artifact_id}.zip")
                with open(archive, 'wb') as fp:
                    gh_api([f"/repos/{repo}/actions/artifacts/{artifact_id}/zip"], stdout=fp)
                artifact_log["archive_name"] = str(archive)
                artifact_log["archive_size"] = archive.stat().st_size

                # Extract JDK and static-libs bundles
                with zipfile.ZipFile(archive, 'r') as zf:
                    for zi in zf.infolist():
                        filename = zi.filename
                        print(f"{archive}!{filename} ({zi.file_size} bytes)")
                        if filename.endswith(".tar.gz") and (filename.startswith("jdk-") or filename.startswith("static-libs")):
                            zf.extract(filename)
                            with tarfile.open(filename, "r:gz") as tf:
                                print(f"unpacking {filename}...")
                                tf.extractall(path="extracted", filter="fully_trusted")
                            Path(filename).unlink()
                archive.unlink()

                # Find java executable
                javas = glob.glob("extracted/jdk*/bin/java")
                assert len(javas) == 1, javas

                java = Path(javas[0])
                java_home = java.parent.parent
                artifact_log["java_home"] = str(java_home)
                artifact_log["java_version"] = subprocess.run(["java", "--version"], capture_output=True, text=True).stdout.strip()

                if not Path("graal").exists():
                    # Clone graal
                    subprocess.run(["gh", "repo", "clone", "oracle/graal", "--", "--quiet", "--branch", "galahad", "--depth", "1"], check=True)

                    # Clone mx
                    subprocess.run(["gh", "repo", "clone", "graalvm/mx", "--", "--quiet", "--branch", "galahad", "--depth", "1"], check=True)
                else:
                    # Clean
                    subprocess.run(["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "clean", "--aggressive"], check=True)

                try:
                    # Build libgraal
                    subprocess.run(["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "build"], check=True)
                    print("building libgraal passed")

                    # Test libgraal
                    subprocess.run(["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "gate", "--task", "LibGraal Compiler:Basic"], check=True)
                    print("testing libgraal passed")
                except subprocess.CalledProcessError as e:
                    artifact_log["error"] = str(e)
                    print(e)
                    failed_pull_requests.append(pr)

                # Remove JDK
                shutil.rmtree(java_home)

        if log:
            log["url"] = pr["html_url"]
            log["head_sha"] = head_sha
            log["run_url"] = run_url

            log = json.dumps(log, indent=2)
            if _verbose:
                print(log)

            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(log)
            log_paths.append(log_path)

    # Push a commit for logs of pull request commits that were tested
    if log_paths:
        git(["config", "user.name", "Doug Simon"])
        git(["config", "user.email", "doug.simon@oracle.com"])

        for log_path in log_paths:
            git(["add", str(log_path)])

        git(["commit", "-m", f"added {len(log_paths)} logs"])
        git(["push"])

    print(f"===================================================")
    print(f"Building and testing libgraal executed for {len(log_paths)} pull requests.")
    print(f"Failures for these pull requests:")
    for pr in failed_pull_requests:
        print(f"  {pr['html_url']} - \"{pr['title']}\"")
    print(f"===================================================")

    # Exit with an error if there were any failures. This ensures
    # the repository owner is notified of the failure.
    if failed_pull_requests:
        raise SystemExit(len(failed_pull_requests))

if __name__ == "__main__":
    main()
