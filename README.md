Overview
========

[GraalVM Native Image](https://www.graalvm.org/) is closely coupled to JDK internals, mostly via substitutions.
As a result, an OpenJDK pull request can break Native Image. Even without breaking Native Image,
an OpenJDK pull request can break Graal itself (e.g. [removing VM symbols exposed to Graal](https://github.com/openjdk/jdk/pull/21401/files#diff-ecc7958e8d833f87874bd145bfaed303d1b516a39321303488d524d871a75930)).
This repository contains a GitHub Actions job that periodically builds and smoke tests
[libgraal](https://medium.com/graalvm/libgraal-graalvm-compiler-as-a-precompiled-graalvm-native-image-26e354bee5c)
against OpenJDK pull requests to provide an early warning system for such breakage.

Details
=======

The [test-openjdk-pullrequests](.github/scripts/test-openjdk-pullrequests.py) script uses the
[GitHub REST API](https://docs.github.com/en/rest) to periodically poll the open, non-draft
pull requests at https://github.com/openjdk/jdk/pulls. For each pull request:
* If there are a `bundles-linux-x64-static` artifact and a `bundles-linux-x64` artifact available, continue.
* Download the `bundles-linux-x64-static` artifact and extract.
* Download the `bundles-linux-x64` artifact and extract the `jdk` bundle.
* Set `JAVA_HOME` to the base directory of the extracted bundles.
* Clone [graal](https://github.com/oracle/graal) and [mx](https://github.com/graalvm/mx).
* Checkout the `galahad` branch in `graal` and `mx`.
* Build and test libgraal. If the build or testing fails, a message is sent to [#openjdk-pr-canary](https://graalvm.slack.com/archives/C07KMA7HFE3)

To avoid repeated testing of a pull request, a test record is committed under
[tested-prs/](tested-prs) for each tested commit of a pull request.
