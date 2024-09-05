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
from datetime import timedelta

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
    text = stdout is None or 'b' not in stdout.mode
    p = subprocess.run(cmd, text=text, capture_output=stdout is None, check=False, stdout=stdout)
    if p.returncode != 0:
        raise Exception(f"Command returned {p.returncode}: {quoted_cmd}{os.linesep}stdout: {p.stdout}{os.linesep}stderr: {p.stderr}")
    if raw or stdout:
        return p.stdout
    return json.loads(p.stdout)

def git(args):
    """
    Runs a git command
    """
    cmd = ["git", "-C", str(_repo_root)] + args
    p = subprocess.run(cmd)
    if p.returncode != 0:
        quoted_cmd = ' '.join(map(shlex.quote, cmd))
        raise Exception(f"non-zero exit code {p.returncode}: {quoted_cmd}")

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

def main(context):
    check_bundle_naming_assumptions()

    # Map from reason for not testing to listed of untested PRs
    untested_prs = {}

    # JSON files for each tested PR
    tested_pr_paths = []

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

        # Skip testing if the head commit has already been tested
        tested_pr_path = Path("tested-prs").joinpath(str(pr["number"]), f"{head_sha}.json")
        logs_dir = Path("results").joinpath("logs", str(pr["number"]), f"{head_sha}")
        if tested_pr_path.exists():
            untested_prs.setdefault("they have previously been tested", []).append(pr)
            continue

        # Pull request test summary
        tested_pr = {}

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
                has_static_libs = False
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

                info(f"processing {pr['html_url']} - {pr['title']}")

                # Find java executable
                java_exes = glob.glob("extracted/jdk*/bin/java")
                assert len(java_exes) == 1, java_exes

                java_exe = Path(java_exes[0])
                java_home = java_exe.parent.parent

                # Artifact test summary
                tested_artifact = tested_pr.setdefault(f"artifact_{artifact_id}", {})

                tested_artifact["java_home"] = str(java_home)
                tested_artifact["java_version_output"] = subprocess.run([str(java_exe), "--version"], capture_output=True, text=True).stdout.strip()

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
                            tested_artifact["failed_step"] = name
                            tested_pr["status"] = "failed"
                            pr["failed_step_log"] = str(log_path)
                            failed_pull_requests.append(pr)
                            raise e
                        finally:
                            info(f"  end: {name}")

                try:
                    if not Path("graal").exists():
                        # Clone graal
                        run_step("clone_graal", ["gh", "repo", "clone", "oracle/graal", "--", "--quiet", "--branch", "galahad", "--depth", "1"])

                        # Clone mx
                        run_step("clone_mx", ["gh", "repo", "clone", "graalvm/mx", "--", "--quiet", "--branch", "galahad", "--depth", "1"])
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

                    tested_pr["status"] = "passed"
                except subprocess.CalledProcessError as e:
                    pass

                # Remove JDK
                shutil.rmtree(java_home)

                context["artifact"] = None

        if tested_pr:
            tested_pr["url"] = pr["html_url"]
            tested_pr["title"] = pr["title"]
            tested_pr["head_sha"] = head_sha
            tested_pr["run_url"] = run_url

            if tested_pr["status"] == "failed":
                post_failure_to_slack(tested_pr)

            tested_pr = json.dumps(tested_pr, indent=2)

            tested_pr_path.parent.mkdir(parents=True, exist_ok=True)
            tested_pr_path.write_text(tested_pr)
            tested_pr_paths.append(tested_pr_path)
        else:
            untested_prs.setdefault(f"they have no {_artifact_to_test} artifact", []).append(pr)

        context["pr"] = None

    # Push a commit for logs of pull request commits that were tested
    if tested_pr_paths:
        git(["config", "user.name", "Doug Simon"])
        git(["config", "user.email", "doug.simon@oracle.com"])

        for tested_pr_path in tested_pr_paths:
            git(["add", str(tested_pr_path)])
            tested_pr = json.loads(tested_pr_path.read_text())
            git(["commit", "--quiet", "-m", f"test record for {tested_pr['url']}\n{tested_pr['title']}"])

        try:
            git(["push", "--quiet"])         
        except Exception as e:
            # Can fail if other commits were pushed in between
            info("pushing pull request test records failed")

    print(f"===================================================")
    if tested_pr_paths:
        print(f"Building and testing libgraal executed for {len(tested_pr_paths)} pull requests.")
        print(f"Logs for all steps are in the 'logs' artifact at {run_url}")
    if failed_pull_requests:
        print(f"Failures for these pull requests:")
        with Path("failure_logs").open("w") as fp:
            for pr in failed_pull_requests:
                failed_step_log = pr['failed_step_log']
                print(failed_step_log, file=fp)
                print(f"  {pr['html_url']} - \"{pr['title']}\"")
                print(f"  log: {failed_step_log}")
                print()
        print(f"Logs for failed steps are shown below in \"Tail logs\".")
    for reason, untested in untested_prs.items():
        print(f"{len(untested)} pull requests not tested because {reason}.")
    print(f"===================================================")

def post_failure_to_slack(tested_pr):
    """
    Posts a message to the #openjdk-pr-testing (https://graalvm.slack.com/archives/C07KMA7HFE3)
    Slack channel for the failure in `tested_pr`.
    """

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
							    "text": "Testing "
						    },
						    {
							    "type": "link",
							    "url": tested_pr["url"]
						    },
                            {
                                "type": "text",
                                "text": " against libgraal failed.\n\nSee the "
                            },
                            {
                                "type": "text",
                                "text": "Test LibGraal",
                                "style": {
                                    "code": True
                                }
                            },
                            {
                                "type": "text",
                                "text": " and "
                            },
                            {
                                "type": "text",
                                "text": "Failure Logs",
                                "style": {
                                    "code": True
                                }
                            },
                            {
                                "type": "text",
                                "text": " sections in the log for the "
                            },
                            {
                                "type": "text",
                                "text": "main",
                                "style": {
                                    "code": True
                                }
                            },
                            {
                                "type": "text",
                                "text": " job at "
                            },
                            {
                                "type": "link",
                                "url": tested_pr["run_url"]
                            },
                            {
                                "type": "text",
                                "text": ".\n\nCoordinate on this channel to adapt to the changes in the pull request. If adaption is non-trivial, consider communicating with the pull request author to request a delay in merging the pull request until the adaption is ready."
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
    cmd = ["curl", "--fail", "--silent", "-X", "POST", "-H", "Content-type: application/json", "--data-binary", f"@{message_path}", os.environ.get('SLACK_WEBHOOK_URL')]
    subprocess.run(cmd, check=True)

if __name__ == "__main__":
    context = {}
    try:
        main(context)
    except Exception as e:
        raise Exception(f"Context for exception in main: {json.dumps(context, indent=2)}") from e

