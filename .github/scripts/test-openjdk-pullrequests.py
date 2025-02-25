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
import re
import urllib.parse
from pathlib import Path
from datetime import timedelta, datetime, timezone

_gh_api_headers = ["-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]
_repo_root = Path(subprocess.run("git rev-parse --show-toplevel".split(), capture_output=True, text=True, check=True).stdout.strip())
_starttime = time.time()

#: Name of OpenJDK artifact to test
_artifact_to_test = "bundles-linux-x64"

def colorize(msg, color):
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
    ansi_color_table = {
        "black": "30",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
    }
    # Make it bright with `;1`
    code = f"{ansi_color_table[color]};1"
    return f"\033[{code}m{msg}\033[0m"

def timestamp():
    duration = timedelta(seconds=time.time() - _starttime)
    # Strip microseconds and convert to a string
    duration = str(duration - timedelta(microseconds=duration.microseconds))
    # Strip hours if 0
    if duration.startswith("0:"):
        duration = duration[2:]
    return time.strftime("%Y-%m-%d %H:%M:%S") + "(+{})".format(duration)


COLOR_WARN = "magenta"
COLOR_ERROR = "red"


def info(msg, color=None):
    """
    Prints the line(s) in `msg`. The prefix of the first line is the current timestamp
    and the prefix for the remaining lines is white space the length of the timestamp.

    :param str|list[str] msg: line(s) of the message to print
    """
    lines = [msg] if not isinstance(msg, list) else msg
    if color:
        lines = [colorize(msg, color) for msg in lines]
    prefix = timestamp()
    print(prefix, lines[0])
    prefix = " " * len(prefix)
    for line in lines[1:]:
        print(prefix, line)


def gh_api(args, stdout=None, raw=False):
    log = Path("results").joinpath("logs", "github_api.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["gh", "api"] + _gh_api_headers + args
    quoted_cmd = " ".join(map(shlex.quote, cmd))
    if stdout:
        quoted_cmd += f" >{stdout.name}"
        # Only attempt a command that redirects to a file once
        remaining_attempts = 1
    else:
        remaining_attempts = 3
    text = stdout is None or "b" not in stdout.mode
    while True:
        with log.open("at") as fp:
            print(f"Command: {quoted_cmd}", file=fp)
        p = subprocess.run(cmd, text=text, capture_output=stdout is None, check=False, stdout=stdout)
        remaining_attempts -= 1
        if p.returncode != 0:
            if stdout:
                stdout_path = Path(stdout.name)
                size = stdout_path.stat().st_size if stdout_path.exists() else 0
                stdout_info = f"<read {size} bytes to {stdout_path}>"
            else:
                stdout_info = f"stdout: {p.stdout}"
            err_msg = f"Command returned {p.returncode}: {quoted_cmd}{os.linesep}{stdout_info}{os.linesep}stderr: {p.stderr}"
            if remaining_attempts == 0:
                raise Exception(err_msg)
            info(f"warning: {err_msg}", COLOR_WARN)
        else:
            break

    if raw or stdout:
        return p.stdout
    with log.open("at") as fp:
        print(f"Stdout: {p.stdout}", file=fp)
    return json.loads(p.stdout)


def git(args, capture_output=False, repo=None):
    """
    Runs a git command
    """
    cmd = ["git", "-C", str(repo or _repo_root)] + args
    p = subprocess.run(cmd, capture_output=capture_output, text=True)
    if p.returncode != 0:
        quoted_cmd = " ".join(map(shlex.quote, cmd))
        stdout = f"\nstdout: {p.stdout}" if capture_output else ""
        stderr = f"\nstderr: {p.stderr}" if capture_output else ""
        guess = ""
        if args[0] == "fetch" and repo in ("graal", "mx"):
            guess = f"\nMaybe mirroring of Graal repos to github is broken?"
        raise Exception(f"non-zero exit code {p.returncode}: {quoted_cmd}{stdout}{stderr}{guess}")
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
    path = get_test_record_path(pr).parent.joinpath(name)
    if not path.exists():
        return []
    return json.loads(path.read_text())


def get_merge_base_commit(pr):
    """
    Gets a json object describing the merge base commit of `pr`.

    The sha and URL for the commit are indexed by "sha" and "html_url"
    respectively in the json object.

    See https://stackoverflow.com/a/77447927/6691595
    """
    merge_base_commit = pr.get("merge_base_commit")
    if merge_base_commit is None:
        head_repo = pr["head"]["repo"]["full_name"]
        base_repo = pr["base"]["repo"]["full_name"]
        head_branch = urllib.parse.quote(pr["head"]["ref"], safe="/:")
        base_branch = "master" # pr["base"]["ref"]
        compare = gh_api([f"/repos/{base_repo}/compare/{base_branch}...{head_repo.replace('/', ':')}:{head_branch}"])
        merge_base_commit = compare["merge_base_commit"]
        pr["merge_base_commit"] = merge_base_commit
    return merge_base_commit


def update_to_match_graal_pr(openjdk_pr, test_record):
    """
    Updates graal and mx to revisions based on the PR at https://github.com/oracle/graal/pulls
    "most associated" with `openjdk_pr`. A graal PR is associated with `openjdk_pr` if the
    graal PR description or comments mention the URL of `openjdk_pr` or its JBS issue id.
    The PR with the most mentions is the most associated PR. The assumption is that it
    is the PR that makes the Graal changes adapting to `openjdk_pr`.

    :returns bool: True if a matching revision was found for graal and mx, False otherwise
    """

    # The key is the PR num and the value is the number of mentions.
    mentions = {}
    m = re.fullmatch(r"(\d{7,}): .*", openjdk_pr["title"])
    openjdk_pr_jbs_issue = f"JDK-{m.group(1)}" if m else None
    openjdk_pr_url = openjdk_pr["html_url"]

    def scan_comment(pr_or_comment):
        body = pr_or_comment["body"]
        refs = 0
        if not body:
            return
        if openjdk_pr_url in body:
            refs += 1
        if openjdk_pr_jbs_issue and openjdk_pr_jbs_issue in body:
            refs += 1
        if refs:
            issue_url = pr_or_comment["issue_url"]
            prefix = "https://api.github.com/repos/oracle/graal/issues/"
            assert issue_url.startswith(prefix), pr_or_comment
            pr_num = issue_url[len(prefix):]
            existing_refs = mentions.get(pr_num, 0)
            mentions[pr_num] = existing_refs + refs

    # Retrieve and scan comments updated in the last 30 days
    since = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
    for pr in gh_api(["--paginate", f"/repos/oracle/graal/pulls?since={since}"]):
        scan_comment(pr)
    for comment in gh_api(["--paginate", f"/repos/oracle/graal/issues/comments?since={since}"]):
        scan_comment(comment)

    if mentions:
        # Iterate in decreasing number of mentions and use first open PR targeting the galahad branch
        for refs, pr_num in sorted(((refs, pr_num) for pr_num, refs in mentions.items()), reverse=True):
            pr = gh_api([f"/repos/oracle/graal/pulls/{pr_num}"])
            if pr["state"] != "open":
                continue
            if pr["base"]["ref"] != "galahad":
                continue
            rev = pr["head"]["sha"]
            git(["fetch", "--quiet", "--depth", "1", "origin", rev], repo="graal")
            git(["reset", "--quiet", "--hard", rev], repo="graal")
            test_record["graal_pr"] = {
                "url": pr["html_url"],
                "number": pr_num,
                "revision": rev
            }
            info(f"  updated graal to revision {rev} from {pr['html_url']} ({refs} mentions of {openjdk_pr_url})")

            common_json = json.loads(Path("graal", "common.json").read_text())
            rev = common_json["mx_version"]
            git(["reset", "--quiet", "--hard", rev], repo="mx")
            info(f"  updated mx to revision {rev} based on graal/common.json")
            return True
    return False

def libgraal_ok(build):
    """
    Determines if the mach5 build in `build` passed the LibGraalPresent test.
    """
    return "LIBGRAAL_BUILD_FAILED" not in build.get("tags", [])

# https://github.com/openjdk/jdk/blob/e7045e9399c5bca0592afc5769432414ecae7219/src/java.base/share/classes/java/lang/Runtime.java#L1577
_vstr_pattern = re.compile(r"([1-9][0-9]*(?:(?:\.0)*\.[1-9][0-9]*)*)(?:-([a-zA-Z0-9]+))?(?:(\+)(0|[1-9][0-9]*)?)?(?:-([-a-zA-Z0-9.]+))?")

def build_sort_key(build):
    """
    Gets the id for `build` as a tuple that sorts ids according to their semantic version interpretation.
    """
    assert build["id"].startswith("jdk-")
    ver = build["id"][4:]
    m = _vstr_pattern.fullmatch(ver)

    def to_ver(s):
        if s is None or s == "+":
            return 0
        return tuple((int(n) for n in s.split(".")))

    return tuple((to_ver(g) for g in m.groups()))

def update_to_match_pr_merge_base(pr):
    """
    Updates graal and mx to a revision in a mach5 build where
    the open jdk revision in the same build is the merge base of the PR.

    :returns bool: True if a matching revision was found for graal and mx, False otherwise
    """

    # Load builds
    builds = json.loads(Path(__file__).parent.joinpath("builds.json").read_text())

    # Sort builds by build ids, oldest to newest.
    # Use the revision from the newest build matching `merge_base_commit`
    newest = None
    merge_base_commit = get_merge_base_commit(pr)
    mbc_sha = merge_base_commit["sha"]
    mbc_url = merge_base_commit["html_url"]
    mbc_desc = f"PR merge base revision [{mbc_sha}]({mbc_url})"
    for build in sorted(builds, key=build_sort_key):
        if mbc_sha in build["revisions"]["open"]:
            newest = build
        elif newest and "__libgraal_ok_successor" not in newest and not libgraal_ok(newest) and libgraal_ok(build):
            newest["__libgraal_ok_successor"] = build

    if newest and not libgraal_ok(newest) and "__libgraal_ok_successor" in newest:
        newest = newest["__libgraal_ok_successor"]
        mbc_desc = f"{mbc_desc} failed to build libgraal - using first succeeding revision with a successful libgraal build in upstream CI"

    if newest:
        info(f"{mbc_desc}")
        info(f"  build id: {newest['id']}")
        for repo in ("graal", "mx"):
            rev = newest["revisions"][repo][0]
            git(["fetch", "--quiet", "--depth", "1", "origin", rev], repo=repo)
            git(["reset", "--quiet", "--hard", rev], repo=repo)
            info(f"  updated {repo} to matching revision {rev}")
        return True

    commit_date = merge_base_commit["commit"]["committer"]["date"]
    delta = datetime.now(timezone.utc) - datetime.fromisoformat(commit_date)
    age_in_hours = delta.total_seconds() / 60 / 60
    if age_in_hours <= 24:
        # This typically happens when a PR merges in the HEAD from master and
        # this commit has not yet been included in a CI build. We speculate
        # that the HEAD of graal and mx is compatible with master HEAD.
        info(
            f"no Galahad EE repo revisions matching the {mbc_desc} but it's less "
            "than 24 hours old so there's a good chance the HEAD of graal and mx are compatible",
            COLOR_WARN,
        )
        for repo in ("graal", "mx"):
            git(["fetch", "--quiet", "--depth", "1", "origin", "galahad"], repo=repo)
            git(["reset", "--quiet", "--hard", "origin/galahad"], repo=repo)
            rev = git(["rev-parse", "HEAD"], capture_output=True, repo=repo).strip()
            info(f"  updated {repo} to HEAD of galahad branch ({rev})")
        return True

    info(f"no Galahad EE repo revisions matching the {mbc_desc}", COLOR_ERROR)
    return False

def add_test_history(test_record, pr, run_url, test_record_path):
    history = git(["log", "--pretty=", "--diff-filter=A", "--name-only", "origin/master", "--", str(test_record_path.parent)], capture_output=True).strip().split()
    if history:
        test_record["history"] = [Path(h).name for h in history]
    else:
        test_record["history"] = []

    test_record["datetime"] = datetime.now(timezone.utc).isoformat()
    test_record["url"] = pr["html_url"]
    test_record["number"] = pr["number"]
    test_record["title"] = pr["title"]
    test_record["head_sha"] = pr["head"]["sha"]
    test_record["run_url"] = run_url


def test_pull_request(pr, artifact, failed_pull_requests):
    """
    Tests `artifact` from `pr`. The artifact's contents are expected to be in $PWD/extracted.

    :return: a dict with the test results
    """
    head_sha = pr["head"]["sha"]

    artifact_id = artifact["id"]
    assert head_sha == artifact["workflow_run"]["head_sha"]

    # Print a bright green line to separate output for each tested PR
    info("--------------------------------------------------------------------------------------", "green")
    info([
        f"processing \"{pr['title']}\"",
        f"           {pr['html_url']} ({head_sha})"
    ])

    # Find java executable
    java_exes = glob.glob("extracted/jdk*/bin/java")
    assert len(java_exes) == 1, java_exes

    java_exe = Path(java_exes[0])
    java_home = java_exe.parent.parent

    # Artifact test record
    artifact_test_record = {}
    test_record = {
        f"artifact_{artifact_id}": artifact_test_record
    }

    artifact_test_record["java_home"] = str(java_home)
    artifact_test_record["java_version_output"] = subprocess.run([str(java_exe), "--version"], capture_output=True, text=True).stdout.strip()

    def run_step(name, cmd, **kwargs):
        assert "capture_output" not in kwargs
        assert "stdout" not in kwargs
        assert "stderr" not in kwargs

        # Convert all command line args to string
        cmd = [str(e) for e in cmd]

        log_path = Path("results").joinpath("logs", str(pr["number"]), head_sha, f"{name}.log")
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
                info(f"non-zero exit code {e.returncode} for step '{name}': " + quoted_cmd, COLOR_ERROR)
                artifact_test_record["failed_step"] = name
                test_record["status"] = "failed"
                pr["failed_step_log"] = str(log_path)
                failed_pull_requests.append(pr)
                pr["__test_record"] = test_record
                raise e
            finally:
                info(f"  end: {name}")

    try:
        if not Path("graal").exists():
            # Clone graal
            run_step("clone_graal", ["gh", "repo", "clone", "oracle/graal", "--", "--quiet", "--branch", "galahad", "--depth", "1"])

            # Clone mx
            run_step("clone_mx", ["gh", "repo", "clone", "graalvm/mx", "--", "--quiet", "--branch", "galahad"])
        else:
            # Clean
            run_step("clean", ["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "clean", "--aggressive"])

        if not update_to_match_graal_pr(pr, test_record) and not update_to_match_pr_merge_base(pr):
            test_record["status"] = "failed"
            failed_pull_requests.append(pr)
            pr["__test_record"] = test_record
        else:
            # Build libgraal
            run_step("build", ["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "build"])

            # Test libgraal
            tasks = [
                "LibGraal Compiler:Basic",
                "LibGraal Compiler:FatalErrorHandling",
                "LibGraal Compiler:SystemicFailureDetection",
                "LibGraal Compiler:CTW",
                # DaCapo 23.11-MR2-chopin is too large to host on GitHub action
                # "LibGraal Compiler:DaCapo"
            ]
            run_step("test", ["mx/mx", "-p", "graal/vm", "--java-home", java_home, "--env", "libgraal", "gate", "--task", ','.join(tasks)])

            test_record["status"] = "passed"
    except subprocess.CalledProcessError:
        pass

    # Remove extracted artifact contents
    shutil.rmtree("extracted")

    return test_record

def push_test_records(test_records):
    """
    Pushes a commit for logs of pull request commits that were tested.
    """
    git(["config", "user.name", "Doug Simon"])
    git(["config", "user.email", "doug.simon@oracle.com"])

    # Before making new commits, pull in any upstream changes so
    # that `git push` below has a better chance of succeeding.
    try:
        git(["pull"])
    except Exception:
        info("pulling upstream changes failed", COLOR_WARN)

    for test_record in test_records:

        if test_record["status"] == "failed":
            post_failure_to_slack(test_record)

        test_record_path = get_test_record_path(test_record)
        if test_record_path.exists():
            info(f"overwriting previous test record in {test_record_path}", COLOR_WARN)
        else:
            test_record_path.parent.mkdir(parents=True, exist_ok=True)
        test_record_path.write_text(json.dumps(test_record, indent=2))

        git(["add", str(test_record_path)])
        git(["commit", "--quiet", "-m", f"test record for pull request {test_record['number']} ({test_record['head_sha']})\n{test_record['title']}"])

    try:
        git(["push", "--quiet"])
    except Exception:
        # Can fail if other commits were pushed in between
        info("pushing pull request test records failed", COLOR_WARN)

    cleanup_closed_prs()

def print_summary(test_records, failed_pull_requests, untested_prs):
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("w") as summary:
        print(f"## Summary of testing OpenJDK pull requests on libgraal", file=summary)
        if test_records:
            print(f"Building and testing libgraal executed for {len(test_records)} pull requests.", file=summary)
            print(f"Logs for all steps are in the `logs` artifact below.", file=summary)
        if failed_pull_requests:
            print(f"Failures for these pull requests:", file=summary)
            with Path("failure_logs").open("w") as fp:
                for pr in failed_pull_requests:
                    failed_step_log = pr.get("failed_step_log", None)
                    if failed_step_log:
                        print(failed_step_log, file=fp)
                    print(f"* [#{pr['number']} - \"{pr['title']}\"]({pr['html_url']})", file=summary)
                    if failed_step_log:
                        print(f"  log: {failed_step_log}", file=summary)
                    history = pr["__test_record"]["history"]
                    if history:
                        history_objs = [load_history(pr, name) for name in history]
                        failures = [e["run_url"] for e in history_objs if e["status"] == "failed"]
                        failures = [f" [{i}]({url})" for i, url in enumerate(failures)]
                        print(f"  previous failures: {', '.join(failures)}", file=summary)

                print(file=summary)

            print(f"Logs for failed steps are shown in the `Failure Logs` section of the `test-pull-requests` job.", file=summary)
        for reason, untested in untested_prs.items():
            print(f"{len(untested)} pull requests not tested because {reason}.", file=summary)

class SlackAPI:
    """
    Object for reading/posting messages from/to a Slack channel.
    """
    def __init__(self):
        self.channel = os.environ.get('SLACK_CHANNEL_ID')
        token = os.environ.get('SLACK_AUTH_TOKEN')
        assert token, f"Required environment variable not set: SLACK_AUTH_TOKEN"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        self.curl_prefix = [
            "curl",
            "--fail",
            "--silent",
            "-X", "POST",
            "-H", "Content-type: application/json",
            "-H", f"Authorization: Bearer {token}"
        ]

    @staticmethod
    def call(cmd):
        p = subprocess.run(cmd, check=True, text=True, capture_output=True)
        response = json.loads(p.stdout)
        if not response["ok"]:
            quoted_cmd = " ".join(map(shlex.quote, cmd))
            err_msg = f"Command returned unexpected response: {quoted_cmd}{os.linesep}stdout: {p.stdout}{os.linesep}stderr: {p.stderr}"
            raise Exception(err_msg)
        return response

    def get_messages(self):
        """
        Gets all top level messages in the channel.
        """
        cursor = ""
        messages = []

        while True:
            url = f"https://slack.com/api/conversations.history?channel={self.channel}&limit=500&{cursor}"
            cmd = self.curl_prefix + [url]
            response = SlackAPI.call(cmd)
            messages = response["messages"] + messages
            if response["has_more"]:
                cursor = "cursor=" + response["response_metadata"]["next_cursor"]
            else:
                return messages

    def post_message(self, message):
        """
        Posts a message to the channel.
        """
        message["channel"] = self.channel
        message_path = Path("message.json")
        message_path.write_text(json.dumps(message))
        cmd = self.curl_prefix + [
            "--data-binary", f"@{message_path}",
            "https://slack.com/api/chat.postMessage"]
        return SlackAPI.call(cmd)

_slack_api = SlackAPI()

def post_failure_to_slack(test_record):
    """
    Posts a message to Slack for the failure in `test_record`.
    """

    pr_title = test_record["title"]
    pr_num = test_record["number"]
    pr_commit = test_record["head_sha"]
    pr_url = test_record["url"]
    run_url = test_record["run_url"]

    key = f"bot:{pr_num}"

    # Slack wraps URLs with "<" and ">" in text messages
    legacy_key = f"bot:<{pr_url}>"

    thread = None
    for message in _slack_api.get_messages():
        if message["text"] in (key, legacy_key):
            thread = message["ts"]
            break

    if not thread:
        # First time failure seen - start a new thread
        message = {
            "text": key,
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
                                    "type": "link",
                                    "text": f"{pr_title} (#{pr_num})",
                                    "url": pr_url
                                }
                            ]
                        }
                    ]
                },
                {
                    "type": "divider"
                }
            ]
        }
        response = _slack_api.post_message(message)
        thread = response["ts"]

    # Add failure to thread
    graal_pr = test_record.get("graal_pr")
    if graal_pr:
        graal_pr_revision = graal_pr["revision"]
        graal_pr_number = graal_pr["number"]
        graal_pr = [
            {
                "type": "text",
                "text": " ("
            },
            {
                "type": "link",
                "text": graal_pr_revision[:14],
                "url": f"https://github.com/oracle/graal/commit/{graal_pr_revision}"
            },
            {
                "type": "text",
                "text": " in "
            },
            {
                "type": "link",
                "text": f"#{graal_pr_number}",
                "url": graal_pr["url"]
            },
            {
                "type": "text",
                "text": ")"
            }
        ]
    else:
        graal_pr = []
    message = {
        "thread_ts": thread,
        "blocks": [
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
                                "text": f" in the above PR against libgraal"
                            }
                        ] + graal_pr + [
                            {
                                "type": "text",
                                "text": f" failed. See "
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
            }
        ]
    }
    _slack_api.post_message(message)

def cleanup_closed_prs():
    """
    Removes test records for closed PRs.
    """
    closed = []
    prs = list(Path("tested-prs").iterdir())
    info(f"Scanning test records for {len(prs)} PRs...")
    for e in prs:
        if e.name.isdigit():
            pr = gh_api([f"/repos/openjdk/jdk/pulls/{e.name}"])
            if pr["state"] == "closed":
                closed.append(e)
    info(f"Found {len(closed)} closed PRs")
    if closed:
        for e in closed:
            shutil.rmtree(e)
            git(["add", str(e)])
        git(["commit", "--quiet", "-m", f"deleted test records for {len(closed)} closed PRs"])
        try:
            git(["push", "--quiet"])
            info(f"Deleted test records for {len(closed)} closed PRs [{','.join((e.name for e in closed))}]")
        except Exception:
            # Can fail if other commits were pushed in between
            info("pushing test record deletion failed", COLOR_WARN)

def get_pr_to_test(untested_prs, failed_pull_requests, visited):
    """
    Finds an upstream PR with an existing artifact that should be tested.

    :return: the `(pr, artifact)` tuple to test or `(None, None)`. In the case of the former,
             the artifact's contents have been extracted to $PWD/extracted.
    """
    prs = gh_api(["--paginate", "/repos/openjdk/jdk/pulls?state=open"])
    for pr in prs:
        pr_num = pr["number"]
        if pr_num in visited:
            continue
        visited.add(pr_num)

        # Ignore pull requests in draft state
        if pr["draft"] is True:
            untested_prs.setdefault("they are in draft state", []).append(pr)
            continue

        # Ignore pull requests whose OCA signatory status is yet to be verified
        if any((l["name"] == "oca" for l in pr["labels"])):
            untested_prs.setdefault("they have unverified OCA signatory status", []).append(pr)
            continue

        # Ignore pull requests that are blocked on a dependent PR
        body = pr["body"]
        if body and re.search(r"Dependency #\d+ must be integrated first", body):
            untested_prs.setdefault("they are blocked on a dependent PR", []).append(pr)
            continue

        # Before starting, fetch commits that may have been pushed between scheduling
        # this job and testing `pr`. This reduces the chance of testing the same pull
        # request commit twice.
        try:
            git(["fetch"])
        except Exception:
            info("fetching upstream changes failed", COLOR_WARN)

        # Skip testing if the head commit has already been tested by looking
        # for the test record in the remote
        test_record_path = get_test_record_path(pr)
        if git(["log", "--pretty=", "--name-only", "origin/master", "--", str(test_record_path)], capture_output=True).strip():
            untested_prs.setdefault("they have previously been tested", []).append(pr)
            continue

        repo = pr["head"]["repo"]["full_name"]
        head_sha = pr["head"]["sha"]

        # Get workflow runs for head commit in pull request
        runs = gh_api([f"/repos/{repo}/actions/runs?head_sha={head_sha}"])

        # Search runs for non-expired artifact
        for run in runs["workflow_runs"]:
            run_id = run["id"]
            # With JDK-8350443, static libs bundle is uploaded in bundles-linux-x64-static
            artifacts_obj_static = gh_api(["--paginate", f"/repos/{repo}/actions/runs/{run_id}/artifacts?name={_artifact_to_test}-static"])
            for artifact in artifacts_obj_static["artifacts"]:
                if not artifact["expired"]:
                    # Download artifact
                    artifact_id = artifact["id"]
                    archive = Path(f"static_lib_{artifact_id}.zip")
                    with open(archive, 'wb') as fp:
                        gh_api([f"/repos/{repo}/actions/artifacts/{artifact_id}/zip"], stdout=fp)

                    # Extract static-libs bundles
                    try:
                        with zipfile.ZipFile(archive, 'r') as zf:
                            zf.extractall(path="extracted", filter="fully_trusted")
                    finally:
                        archive.unlink()

                    break

            artifacts_obj = gh_api(["--paginate", f"/repos/{repo}/actions/runs/{run_id}/artifacts?name={_artifact_to_test}"])
            for artifact in artifacts_obj["artifacts"]:
                if not artifact["expired"]:

                    # Download artifact
                    artifact_id = artifact["id"]
                    archive = Path(f"jdk_{artifact_id}.zip")
                    with open(archive, 'wb') as fp:
                        gh_api([f"/repos/{repo}/actions/artifacts/{artifact_id}/zip"], stdout=fp)

                    # Extract JDK and static-libs bundles
                    try:
                        with zipfile.ZipFile(archive, 'r') as zf:
                            if not (os.path.isdir("extracted") and os.listdir("extracted")):
                                # Check if pr is pre JDK-8350443, i.e., with static libs bundled with the same zip
                                if not any((zi.filename.startswith("static-libs") for zi in zf.infolist())):
                                    failed_pull_requests.append(pr)
                                    continue

                            for zi in zf.infolist():
                                filename = zi.filename
                                if filename.endswith(".tar.gz") and (filename.startswith("jdk-") or filename.startswith("static-libs")):
                                    zf.extract(filename)
                                    with tarfile.open(filename, "r:gz") as tf:
                                        tf.extractall(path="extracted", filter="fully_trusted")
                                    Path(filename).unlink()
                    finally:
                        archive.unlink()

                    return pr, artifact

    return None, None

def main():
    check_bundle_naming_assumptions()

    # Map from reason for not testing to listed of untested PRs
    untested_prs = {}

    # List of dicts capturing details of pull requests that were tested
    test_records = []

    # URL for the current GitHub Action workflow run
    run_url = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}"

    # Pull requests for which libgraal building or testing failed
    failed_pull_requests = []

    visited = set()
    while True:
        pr, artifact = get_pr_to_test(untested_prs, failed_pull_requests, visited)
        if not pr:
            break

        test_record = test_pull_request(pr, artifact, failed_pull_requests)
        if test_record:
            test_record_path = get_test_record_path(pr)
            add_test_history(test_record, pr, run_url, test_record_path)
            test_records.append(test_record)
        else:
            untested_prs.setdefault(f"they have no {_artifact_to_test} artifact", []).append(pr)

    if test_records:
        push_test_records(test_records)

    print_summary(test_records, failed_pull_requests, untested_prs)

if __name__ == "__main__":
    info("Enter Canary")
    try:
        main()
    finally:
        info("Exit Canary")
