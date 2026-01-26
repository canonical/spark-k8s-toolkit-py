#!/usr/bin/env python3
# Copyright 2026 Canonical Limited
# See LICENSE file for licensing details.

"""Simple Spark test that runs inside the pod with real Spark runtime."""

import os
from spark8t.session import SparkSession

# Get namespace and username from environment
namespace = os.environ.get("SPARK_NAMESPACE", "default")
username = os.environ.get("SPARK_USERNAME", "spark-test-user")

# Test when namespace and username explicitly provided
with SparkSession(
    app_name="spark-trivial-test",
    namespace=namespace,
    username=username,
) as session:
    # Do a trivial operation
    rdd = session.sparkContext.parallelize([1, 2, 3])
    result = rdd.collect()
    print(f"Result: {result}")
    assert result == [1, 2, 3], f"Expected [1, 2, 3] but got {result}"


# Test when namespace and username inferred from env vars
with SparkSession(
    app_name="spark-trivial-test",
) as session:
    # Do a trivial operation
    rdd = session.sparkContext.parallelize([1, 2, 3])
    result = rdd.collect()
    print(f"Result: {result}")
    assert result == [1, 2, 3], f"Expected [1, 2, 3] but got {result}"


print("Test completed successfully.")
