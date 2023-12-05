# spark8t toolkit

[![Release](https://github.com/canonical/spark-k8s-toolkit-py/actions/workflows/release_github.yaml/badge.svg)](https://github.com/canonical/spark-k8s-toolkit-py/actions/workflows/release_github.yaml)
[![Tests](https://github.com/canonical/spark-k8s-toolkit-py/actions/workflows/ci-tests.yaml/badge.svg?branch=main)](https://github.com/canonical/spark-k8s-toolkit-py/actions/workflows/ci-tests.yaml?query=branch%3Amain)

A set of Python scripts facilitating Spark interactions over Kunernetes, using an OCI image.

## Description

The main purpose of the `spark8t` toolkit is to provide a seemless, user-friendly interface
to Spark functionalities over Kubernetes. As much for administator tasks (such as account registration)
or data scientist functions (such as job submission or Spark interactive shell access). Various
wrapper scripts allow for persistent (and user-friendly) configuration and execution of related tools.

## Dependencies and Requirements

 - *Kubernetes*
 - *Apache Spark*

## Installation

Below we describe the essential steps on how to set up a Spark cluster together with the `spark8t` tool.

(However note that most of the "hassle" desribed below can be saved, in case you choose to use the 
[canonical/spark-client-snap](canonical/spark-client-snap) Snap installation, that would both install
dependencies, both prepare critical parts of the environment for you.)

### Kubernetes

In order to be able to run Spark on Kubernetes, you'll sure need to have a Kubernetes cluster installed :-)

A simple installation of a lightweight Kubernetes implementation (Canonical's `microk8s`) can
be found in our [Discourse Spark
Tutorial](https://discourse.charmhub.io/t/spark-client-snap-tutorial-setup-environment/8951)

Keep in mind to set the following environment variable:

 - `KUBECONFIG`: the location of the Kubernetes cluster configuration (typically: /home/$USER/.kube/config)

### Spark

You will need to install Spark as instructed at the official [Apache Spark pages](https://spark.apache.org/downloads.html).

Related settings:

 - `SPARK_HOME`: location of your Spark installation

### spark8t

You could install the contents of this repository either by direct checkout, or using `pip` such as

```
pip insatll git+https://github.com/canonical/spark-k8s-toolkit-py.git
```

You'll need to add a mandatory configuration for the tool, which points to the OCI image to be used for the Spark workers.
The configuration file must be called `spark-defaults.conf`, and could have a list of contents according to possible
Spark-accepted command-line parameters. However the following specific one has to be defined:

```
spark.kubernetes.container.image=ghcr.io/canonical/charmed-spark:<version>
```

(See the [Spark ROCK releases GitHub page](https://github.com/canonical/charmed-spark-rock/pkgs/container/charmed-spark) for available versions)

Then you would need to assign the correct values for the following `spark8t` environment variables:

 - `SPARK_CONFS`: location of the `spark8t` configuration file
 - `HOME`: the home of the Spark user (typically: `/home/spark`)
 - `SPARK_USER_DATA`: the location of Spark user data, such as interactive shell history (typically: same as `HOME`)

## Basic Usage

`spark8t` is "built around" Spark itself, thus the usage is very similar to the known Spark client tools.

The toolkit offers access to Spark functionalities via two interfaces:

 - interactive CLI
 - programmatic access via the underlying Python library

We provide the following functionalities (see related documentation on Discourse):

- [management of the Account Registry](https://discourse.charmhub.io/t/spark-client-snap-tutorial-manage-spark-service-accounts/8952)
- [job submission](https://discourse.charmhub.io/t/spark-client-snap-tutorial-spark-submit/8953)
- [interactive shell (Python, Scala)](https://discourse.charmhub.io/t/spark-client-snap-tutorial-interactive-mode/8954)
- [programmatic access](https://discourse.charmhub.io/t/spark-client-snap-how-to-python-api/8958)

## Contributing

Canonical welcomes contributions to the `spark8t` toolkit. Please check out our [guidelines](./CONTRIBUTING.md) if you're interested in contributing to the solution. Also, if you truly enjoy working on open-source projects like this one and you would like to be part of the OSS revolution, please don't forget to check out the [open positions](https://canonical.com/careers/all) we have at [Canonical](https://canonical.com/).  

## License
The `spark8t` toolkit is free software, distributed under the Apache Software License, version 2.0. See LICENSE for more information.

See [LICENSE](LICENSE) for more information.
