"""Orchestrator integration tests that deploy SparkSession tests to a pod."""

import os
import time
import subprocess
import tempfile
import pytest
import yaml
from pathlib import Path

from lightkube import Client
from lightkube.resources.core_v1 import Pod


@pytest.mark.usefixtures("integration_test")
class TestSparkSessionPodDeployment:
    """Tests that orchestrate Spark job execution in a Kubernetes pod."""

    @staticmethod
    def _render_pod_spec(
        namespace: str, service_account_name: str, repo_path: str
    ) -> str:
        """Render the pod spec template with actual namespace and service account.

        Returns the rendered YAML as a string.
        """
        template_path = (
            Path(__file__).parent / "resources" / "spark-session-test-driver.yaml"
        )
        with open(template_path) as f:
            template = f.read()

        # Replace template variables
        rendered = (
            template.replace("{{ NAMESPACE }}", namespace)
            .replace("{{ SERVICE_ACCOUNT_NAME }}", service_account_name)
            .replace("{{ REPO_PATH }}", repo_path)
        )

        return rendered

    @staticmethod
    def _wait_for_pod_completion(
        client: Client, namespace: str, pod_name: str, timeout: int = 600
    ) -> bool:
        """Wait for pod to complete and return True if successful."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            pod = client.get(Pod, name=pod_name, namespace=namespace)
            assert pod is not None
            assert pod.status is not None

            status = pod.status.phase

            if status == "Succeeded":
                return True
            elif status == "Failed":
                return False
            elif status == "Unknown":
                return False

            time.sleep(5)

        return False

    @staticmethod
    def _get_pod_logs(namespace: str, pod_name: str) -> str:
        """Get the logs from the test pod."""
        try:
            result = subprocess.run(
                ["kubectl", "logs", "-n", namespace, pod_name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout
        except Exception as e:
            return f"Could not retrieve logs: {str(e)}"

    def test_spark_jobs_run_in_pod(self, service_account):
        """Test that Spark jobs actually run and succeed in a pod."""
        service_account_name, namespace = service_account

        # Render pod spec with actual namespace, service account, and repo path
        repo_path = str(Path(__file__).parent.parent.parent.absolute())
        pod_spec_yaml = self._render_pod_spec(
            namespace, service_account_name, repo_path
        )

        # Apply the pod spec using kubectl
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(pod_spec_yaml)
            spec_file = f.name

        try:
            subprocess.run(
                ["kubectl", "apply", "-f", spec_file], check=True, capture_output=True
            )

            # Extract pod name from the spec
            spec_dict = yaml.safe_load(pod_spec_yaml)
            pod_name = spec_dict["metadata"]["name"]

            # Wait for pod to complete (with timeout)
            client = Client()
            success = self._wait_for_pod_completion(
                client, namespace, pod_name, timeout=600
            )

            # Get and print logs
            logs = self._get_pod_logs(namespace, pod_name)
            print("\n" + "=" * 80)
            print(f"Pod logs for {pod_name}:")
            print("=" * 80)
            print(logs)
            print("=" * 80)

            # Verify pod succeeded
            assert success, (
                f"Pod {pod_name} did not complete successfully. Check logs above."
            )

            # Verify success markers in logs
            assert "Spark integration test completed successfully!" in logs, (
                "Script did not report successful completion"
            )
            assert "✓ Spark session works!" in logs, (
                "Spark session did not execute successfully"
            )
        finally:
            # Clean up temp file
            os.unlink(spec_file)
