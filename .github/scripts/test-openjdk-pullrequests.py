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
import time
import glob
from argparse import ArgumentParser
from pathlib import Path
from datetime import timedelta, datetime

_gh_api_headers = ["-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]
_repo_root = Path(subprocess.run("git rev-parse --show-toplevel".split(), capture_output=True, text=True, check=True).stdout.strip())
_starttime = time.time()

#: Name of OpenJDK artifact to test
_artifact_to_test = "bundles-linux-x64"

def timestamp():
    duration = timedelta(seconds=time.time() - _starttime)
    # Strip microseconds and convert to a string
    duration = str(duration - timedelta(microseconds=duration.microseconds))
    # Strip hours if 0
    if duration.startswith('0:'):
        duration = duration[2:]
    return time.strftime('%Y-%m-%d %H:%M:%S') + '(+{})'.format(duration)

def info(msg):
    print(f"{timestamp()} {msg}")

def gh_api(args, stdout=None, raw=False):
    cmd = ["gh", "api"] + _gh_api_headers + args
    quoted_cmd = ' '.join(map(shlex.quote, cmd))
    if stdout:
        quoted_cmd += f" >{stdout.name}"
        # Only attempt a command that redirects to a file once
        remaining_attempts = 1
    else:
        remaining_attempts = 3
    text = stdout is None or 'b' not in stdout.mode
    while True:
        p = subprocess.run(cmd, text=text, capture_output=stdout is None, check=False, stdout=stdout)
        remaining_attempts -= 1
        if p.returncode != 0:
            err_msg = f"Command returned {p.returncode}: {quoted_cmd}{os.linesep}stdout: {p.stdout}{os.linesep}stderr: {p.stderr}"
            if remaining_attempts == 0:
                raise Exception(err_msg)
            else:
                info(f"warning: {err_msg}")
        else:
            break

    if raw or stdout:
        return p.stdout
    return json.loads(p.stdout)

def git(args, capture_output=False, repo=None):
    """
    Runs a git command
    """
    cmd = ["git", "-C", str(repo or _repo_root)] + args
    p = subprocess.run(cmd, capture_output=capture_output, text=True)
    if p.returncode != 0:
        quoted_cmd = ' '.join(map(shlex.quote, cmd))
        stdout = f"\nstdout: {p.stdout}" if capture_output else ""
        raise Exception(f"non-zero exit code {p.returncode}: {quoted_cmd}{stdout}")
    return p.stdout

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

def get_test_record_path(pr):
    head_sha = pr.get("head_sha") if "head_sha" in pr else pr["head"]["sha"]
    return Path("tested-prs").joinpath(str(pr["number"]), f"{head_sha}.json")

def load_history(pr, name):
    return json.loads(get_test_record_path(pr).parent.joinpath(name).read_text())

def main(context):

    check_bundle_naming_assumptions()

    # Map from reason for not testing to listed of untested PRs
    untested_prs = {}

    # List of dicts capturing details of pull requests that were tested
    test_records = []

    # URL for the current GitHub Action workflow run
    run_url = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}"

    # Pull requests for which libgraal building or testing failed
    failed_pull_requests = []

    prs = gh_api(["--paginate", "/repos/openjdk/jdk/pulls?state=open"])
    for pr in prs:
        context["pr"] = pr
        # Ignore pull requests in draft state
        if pr["draft"] is True:
            untested_prs.setdefault("they are in draft state", []).append(pr)
            continue

        # Ignore pull requests whose OCA signatory status is yet to be verified
        if any((l["name"] == "oca" for l in pr["labels"])):
            untested_prs.setdefault("they have unverified OCA signatory status", []).append(pr)
            continue

        repo = pr["head"]["repo"]["full_name"]
        head_sha = pr["head"]["sha"]
        base_sha = pr["base"]["sha"]

        # Before starting, fetch commits that may have been pushed between scheduling
        # this job and testing `pr`. This reduces the chance of testing the same pull
        # request commit twice.
        try:
            git(["fetch"])
        except Exception as e:
            info("fetching upstream changes failed")

        # Skip testing if the head commit has already been tested by looking
        # for the test record in the remote
        test_record_path = get_test_record_path(pr)
        if git(["log", "--pretty=", "--name-only", "origin/master", "--", str(test_record_path)], capture_output=True).strip():
            untested_prs.setdefault("they have previously been tested", []).append(pr)
            continue

        logs_dir = Path("results").joinpath("logs", str(pr["number"]), f"{head_sha}")

        # Pull request test record
        test_record = {}

        # Get workflow runs for head commit in pull request
        runs = gh_api([f"/repos/{repo}/actions/runs?head_sha={head_sha}"])

        # Search runs for non-expired artifact
        for run in runs["workflow_runs"]:
            run_id = run["id"]
            artifacts_obj = gh_api(["--paginate", f"/repos/{repo}/actions/runs/{run_id}/artifacts?name={_artifact_to_test}"])
            for artifact in artifacts_obj["artifacts"]:
                context["artifact"] = artifact
                if artifact["expired"]:
                    continue

                artifact_id = artifact["id"]

                # Download artifact
                archive = Path(f"jdk_{artifact_id}.zip")
                with open(archive, 'wb') as fp:
                    gh_api([f"/repos/{repo}/actions/artifacts/{artifact_id}/zip"], stdout=fp)

                # Extract JDK and static-libs bundles
                with zipfile.ZipFile(archive, 'r') as zf:
                    if not any((zi.filename.startswith("static-libs") for zi in zf.infolist())):
                        untested_prs.setdefault("they are missing the static-libs bundle (added by JDK-8337265)", []).append(pr)
                        continue

                    for zi in zf.infolist():
                        filename = zi.filename
                        if filename.endswith(".tar.gz") and (filename.startswith("jdk-") or filename.startswith("static-libs")):
                            zf.extract(filename)
                            with tarfile.open(filename, "r:gz") as tf:
                                tf.extractall(path="extracted", filter="fully_trusted")
                            Path(filename).unlink()
                archive.unlink()

                info(f"processing {pr['html_url']} ({head_sha}) - {pr['title']}")

                # Find java executable
                java_exes = glob.glob("extracted/jdk*/bin/java")
                assert len(java_exes) == 1, java_exes

                java_exe = Path(java_exes[0])
                java_home = java_exe.parent.parent

                # Artifact test record
                artifact_test_record = test_record.setdefault(f"artifact_{artifact_id}", {})

                artifact_test_record["java_home"] = str(java_home)
                artifact_test_record["java_version_output"] = subprocess.run([str(java_exe), "--version"], capture_output=True, text=True).stdout.strip()

                def run_step(name, cmd, **kwargs):
                    assert "capture_output" not in kwargs
                    assert "stdout" not in kwargs
                    assert "stderr" not in kwargs

                    # Convert all command line args to string
                    cmd = [str(e) for e in cmd]

                    log_path = logs_dir.joinpath(f"{name}.log")
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    info(f"begin: {name}")
                    with log_path.open("w") as fp:
                        kwargs["stdout"] = fp
                        kwargs["stderr"] = subprocess.STDOUT
                        kwargs["check"] = True
                        try:
                            subprocess.run(cmd, **kwargs)
                        except subprocess.CalledProcessError as e:
                            quoted_cmd = ' '.join(map(shlex.quote, cmd))
                            info(f"non-zero exit code {e.returncode} for step '{name}': " + quoted_cmd)
                            artifact_test_record["failed_step"] = name
                            test_record["status"] = "failed"
                            pr["failed_step_log"] = str(log_path)
                            failed_pull_requests.append(pr)
                            pr["__test_record"] = test_record
                            raise e
                        finally:
                            info(f"  end: {name}")

                def update_to_match_pr_base(repo, builds):
                    """
                    Updates the local clone in `repo` to a revision in a mach5 build where
                    the open jdk revision in the same build is the one the PR is based on.
                    """

                    # Sort builds by build ids, oldest to newest.
                    # Use the revision from the newest build matching `base_sha`
                    newest = None
                    for build in sorted(builds, key=lambda b: b["id"]):
                        if build["revisions"]["open"] == base_sha:
                            newest = build["revisions"]
                    if newest:
                        info(f"updating {repo} to revision matching PR base")
                        git(["fetch", "--depth", "1", "origin", newest[repo]], repo=repo)
                    else:
                        info(f"no {repo} revision matching {base_sha}")

                try:
                    if not Path("graal").exists():
                        # Load builds
                        builds = json.loads(Path(__file__).parent.joinpath("builds.json").read_text())

                        # Clone graal
                        run_step("clone_graal", ["gh", "repo", "clone", "oracle/graal", "--", "--quiet", "--branch", "galahad", "--depth", "1"])
                        update_to_match_pr_base("graal", builds)

                        # Clone mx
                        run_step("clone_mx", ["gh", "repo", "clone", "graalvm/mx", "--", "--quiet", "--branch", "galahad", "--depth", "1"])
                        update_to_match_pr_base("mx", builds)
                    else:
                        # Clean
                        run_step("clean", ["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "clean", "--aggressive"])

                    # Build libgraal
                    run_step("build", ["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "build"])

                    # Test libgraal
                    tasks = [
                        "LibGraal Compiler:Basic",
                        "LibGraal Compiler:FatalErrorHandling",
                        "LibGraal Compiler:SystemicFailureDetection",
                        "LibGraal Compiler:CTW",
                        "LibGraal Compiler:DaCapo"
                    ]
                    run_step("test", ["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "gate", "--task", ','.join(tasks)])

                    test_record["status"] = "passed"
                except subprocess.CalledProcessError as e:
                    pass

                # Remove JDK
                shutil.rmtree(java_home)

                context["artifact"] = None

        if test_record:
            # Add test history
            history = git(["log", "--pretty=", "--diff-filter=A", "--name-only", "origin/master", "--", str(test_record_path.parent)], capture_output=True).strip().split()
            if history:
                test_record["history"] = [Path(h).name for h in history]
            else:
                test_record["history"] = []

            test_record["datetime"] = datetime.now().isoformat()
            test_record["url"] = pr["html_url"]
            test_record["number"] = pr["number"]
            test_record["title"] = pr["title"]
            test_record["head_sha"] = head_sha
            test_record["run_url"] = run_url

            if test_record["status"] == "failed":
                post_failure_to_slack(test_record)

            test_records.append(test_record)
        else:
            untested_prs.setdefault(f"they have no {_artifact_to_test} artifact", []).append(pr)

        context["pr"] = None

    # Push a commit for logs of pull request commits that were tested
    if test_records:
        git(["config", "user.name", "Doug Simon"])
        git(["config", "user.email", "doug.simon@oracle.com"])

        # Before making new commits, pull in any upstream changes so
        # that `git push` below has a better chance of succeeding.
        try:
            git(["pull"])
        except Exception as e:
            info("pulling upstream changes failed")

        for test_record in test_records:
            test_record_path = get_test_record_path(test_record)
            if test_record_path.exists():
                info(f"overwriting previous test record in {test_record_path}")
            else:
                test_record_path.parent.mkdir(parents=True, exist_ok=True)
            test_record_path.write_text(json.dumps(test_record, indent=2))

            git(["add", str(test_record_path)])
            git(["commit", "--quiet", "-m", f"test record for pull request {test_record['number']} ({test_record['head_sha']})\n{test_record['title']}"])

        try:
            git(["push", "--quiet"])         
        except Exception as e:
            # Can fail if other commits were pushed in between
            info("pushing pull request test records failed")

    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("w") as summary:
        print(f"## Summary of testing OpenJDK pull requests on libgraal", file=summary)
        if test_records:
            print(f"Building and testing libgraal executed for {len(test_records)} pull requests.", file=summary)
            print(f"Logs for all steps are in the `logs` artifact below.", file=summary)
        if failed_pull_requests:
            print(f"Failures for these pull requests:", file=summary)
            with Path("failure_logs").open("w") as fp:
                for pr in failed_pull_requests:
                    failed_step_log = pr['failed_step_log']
                    print(failed_step_log, file=fp)
                    print(f"* [#{pr['number']} - \"{pr['title']}\"]({pr['html_url']})", file=summary)
                    print(f"  log: {failed_step_log}", file=summary)
                    history = pr["__test_record"]["history"]
                    if history:
                        history_objs = [load_history(pr, name) for name in history]
                        failures = [e["run_url"] for e in history_objs if e["status"] == "failed"]
                        failures = [f" [{i}]({url})" for i, url in enumerate(failures)]
                        print(f"  previous failures: {failures}", file=summary)

                print(file=summary)

            print(f"Logs for failed steps are shown in the `Failure Logs` section of the `test-pull-requests` job.", file=summary)
        for reason, untested in untested_prs.items():
            print(f"{len(untested)} pull requests not tested because {reason}.", file=summary)

def post_failure_to_slack(test_record):
    """
    Posts a message to the #openjdk-pr-canary (https://graalvm.slack.com/archives/C07KMA7HFE3)
    Slack channel for the failure in `test_record`.
    """

    pr_num = test_record['number']
    pr_commit = test_record['head_sha']
    pr_url = test_record["url"]
    run_url = test_record["run_url"]

    history = test_record["history"]
    history_objs = [load_history(test_record, name) for name in history]
    failures = [e for e in history_objs if e["status"] == "failed"]
    if failures:
        previous_failures = [
            {
                "type": "text",
                "text": f" ({len(failures)} previous failures"
            },
            {
                "type": "emoji",
                "name": "point_up"
            },
            {
                "type": "text",
                "text": ")"
            }
        ]
    else:
        previous_failures = []

    message = json.dumps({
        "blocks": [
            {
                "type": "divider"
            },
            {
                "type": "rich_text",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": f"Testing commit "
                            },
                            {
                                "type": "link",
                                "text": f"{pr_commit[:14]}",
                                "url": f"{pr_url}/commits/{pr_commit}"
                            },
                            {
                                "type": "text",
                                "text": f" in "
                            },
                            {
                                "type": "link",
                                "text": f"#{pr_num}",
                                "url": pr_url
                            },
                            {
                                "type": "text",
                                "text": " against libgraal failed"
                            }
                        ] + previous_failures + [
                            {
                                "type": "text",
                                "text": ". See "
                            },
                            {
                                "type": "link",
                                "text": "this summary",
                                "url": run_url
                            },
                            {
                                "type": "text",
                                "text": "."
                            }
                        ]
                    }
                ]
            },
            {
                "type": "divider"
            }
        ]
    })
    
    message_path = Path("message.json")
    message_path.write_text(message)
    cmd = ["curl", "--fail", "--silent", "-X", "POST",
               "-H", "Content-type: application/json",
               "--data-binary", f"@{message_path}",
               os.environ.get('SLACK_WEBHOOK_URL')]
    subprocess.run(cmd, check=True)

if __name__ == "__main__":
    context = {}
    try:
        main(context)
    except Exception as e:
        raise Exception(f"Context for exception: {json.dumps(context, indent=2)}") from e
