Overview
========

Libgraal is built with SVM and SVM is closely tied to JDK internals. As a result, an OpenJDK pull request can break building libgraal.
This repository contains a GitHub Actions job that periodically tests libgraal against open OpenJDK pull requests to provide an
early warning system for such breakage. It gives the Graal team time to prepare changes that adapt to the OpenJDK change.

Details
=======

The [test-openjdk-pullrequests](.github/scripts/test-openjdk-pullrequests.py) script uses the
[GitHub REST API](https://docs.github.com/en/rest) to periodically poll the open, non-draft
pull requests at https://github.com/openjdk/jdk/pulls. For each pull request:
* If there is a `bundles-linux-x64` artifact available, continue.
* Download the `bundles-linux-x64` artifact and extract the `jdk` and `static-libs` bundles.
* Set `JAVA_HOME` to the base directory of the extracted bundles.
* Clone [graal](https://github.com/oracle/graal) and [mx](https://github.com/graalvm/mx).
* Checkout the `galahad` branch in `graal` and `mx`.
* Build and test libgraal.

If any of the above steps fail, the workflow fails and the owner of this repo is notified.
To avoid repeated testing of a pull request commit, a test record is committed under
[logs/](logs) for each tested commit.