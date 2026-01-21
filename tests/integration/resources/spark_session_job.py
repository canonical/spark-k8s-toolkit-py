"""Simple Spark test that runs inside the pod with real Spark runtime."""

import os
from lightkube import Client
from spark8t.session import SparkSession

# Get namespace and username from environment
namespace = os.environ.get("SPARK_NAMESPACE", "default")
username = os.environ.get("SPARK_USERNAME", "spark-test-user")

k8s_master_ip = (
    Client()
    .config.cluster.server.replace("https://", "")
    .replace("http://", "")
    .split(":")[0]
)

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
    assert k8s_master_ip in os.environ["no_proxy"]
    assert k8s_master_ip in os.environ["NO_PROXY"]
    assert session.username == username
    assert session.namespace == namespace


# Test when namespace and username inferred from env vars
with SparkSession(
    app_name="spark-trivial-test",
) as session:
    # Do a trivial operation
    rdd = session.sparkContext.parallelize([1, 2, 3])
    result = rdd.collect()
    print(f"Result: {result}")
    assert result == [1, 2, 3], f"Expected [1, 2, 3] but got {result}"
    assert k8s_master_ip in os.environ["no_proxy"]
    assert k8s_master_ip in os.environ["NO_PROXY"]
    assert session.username == username
    assert session.namespace == namespace

print("Test completed successfully.")
