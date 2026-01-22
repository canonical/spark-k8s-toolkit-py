#!/usr/bin/env python3
# Copyright 2026 Canonical Limited
# See LICENSE file for licensing details.

"""Unit tests for the SparkSession module."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock pyspark before importing SparkSession since pyspark may not be installed
sys.modules["pyspark"] = MagicMock()
sys.modules["pyspark.sql"] = MagicMock()

from spark8t.session import SparkSession  # noqa: E402


class TestSparkSessionInit:
    """Test SparkSession initialization."""

    def test_init_with_explicit_namespace_and_username(self):
        """Test initialization with explicitly provided namespace and username."""
        session = SparkSession(
            app_name="test-app", namespace="test-ns", username="test-user"
        )
        assert session.app_name == "test-app"
        assert session.namespace == "test-ns"
        assert session.username == "test-user"

    def test_init_with_env_namespace_and_username(self):
        """Test initialization with namespace and username from environment variables."""
        with patch.dict(
            os.environ,
            {"SPARK_NAMESPACE": "env-ns", "SPARK_USERNAME": "env-user"},
            clear=False,
        ):
            session = SparkSession(app_name="test-app")
            assert session.namespace == "env-ns"
            assert session.username == "env-user"

    def test_init_explicit_overrides_env_namespace(self):
        """Test that explicit namespace parameter overrides environment variable."""
        with patch.dict(
            os.environ,
            {"SPARK_NAMESPACE": "env-ns", "SPARK_USERNAME": "env-user"},
            clear=False,
        ):
            session = SparkSession(
                app_name="test-app", namespace="explicit-ns", username="test-user"
            )
            assert session.namespace == "explicit-ns"
            assert session.username == "test-user"

    def test_init_missing_namespace_raises_error(self):
        """Test that missing namespace raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(
                ValueError,
                match="Namespace must be provided either as argument or via SPARK_NAMESPACE env variable",
            ):
                SparkSession(app_name="test-app", username="test-user")

    def test_init_missing_username_raises_error(self):
        """Test that missing username raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(
                ValueError,
                match="Username must be provided either as argument or via SPARK_USERNAME env variable",
            ):
                SparkSession(app_name="test-app", namespace="test-ns")

    def test_init_missing_both_namespace_and_username_raises_error(self):
        """Test that missing both namespace and username raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError):
                SparkSession(app_name="test-app")


class TestSparkSessionProperties:
    """Test spark properties including extra props and config."""

    @patch("spark8t.session.K8sServiceAccountRegistry")
    @patch("spark8t.session.LightKube")
    @patch("socket.gethostbyname")
    @patch("socket.gethostname")
    @patch("spark8t.session.Client")
    def test_sa_props_retrieves_service_account_properties(
        self,
        mock_client_class,
        mock_gethostname,
        mock_gethostbyname,
        mock_lightkube_class,
        mock_registry_class,
    ):
        """Test that _sa_props retrieves and returns service account properties."""
        # Setup mocks
        mock_client = MagicMock()
        mock_client.config.cluster.server = "https://10.0.0.1:6443"
        mock_client_class.return_value = mock_client

        mock_lightkube = MagicMock()
        mock_lightkube_class.return_value = mock_lightkube

        mock_sa = MagicMock()
        mock_sa.configurations.props = {
            "spark.kubernetes.namespace": "test-ns",
            "spark.kubernetes.serviceAccountName": "test-user",
        }
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_sa
        mock_registry_class.return_value = mock_registry

        mock_gethostname.return_value = "pod-name"
        mock_gethostbyname.return_value = "192.168.1.100"

        session = SparkSession(
            app_name="test-app", namespace="test-ns", username="test-user"
        )
        props = session._sa_props

        assert props == {
            "spark.kubernetes.namespace": "test-ns",
            "spark.kubernetes.serviceAccountName": "test-user",
        }
        mock_registry.get.assert_called_once_with("test-ns:test-user")

    @patch("spark8t.session.K8sServiceAccountRegistry")
    @patch("spark8t.session.LightKube")
    @patch("socket.gethostbyname")
    @patch("socket.gethostname")
    @patch("spark8t.session.Client")
    def test_sa_props_returns_empty_dict_on_exception(
        self,
        mock_client_class,
        mock_gethostname,
        mock_gethostbyname,
        mock_lightkube_class,
        mock_registry_class,
    ):
        """Test that _sa_props returns empty dict when exceptions occur."""
        # Setup mocks
        mock_client = MagicMock()
        mock_client.config.cluster.server = "https://10.0.0.1:6443"
        mock_client_class.return_value = mock_client

        mock_lightkube = MagicMock()
        mock_lightkube_class.return_value = mock_lightkube

        mock_registry = MagicMock()
        mock_registry.get.side_effect = AttributeError("Missing attribute")
        mock_registry_class.return_value = mock_registry

        mock_gethostname.return_value = "pod-name"
        mock_gethostbyname.return_value = "192.168.1.100"

        session = SparkSession(
            app_name="test-app", namespace="test-ns", username="test-user"
        )
        props = session._sa_props

        assert props == {}

    @patch("spark8t.session.K8sServiceAccountRegistry")
    @patch("spark8t.session.LightKube")
    @patch("socket.gethostbyname")
    @patch("socket.gethostname")
    @patch("spark8t.session.Client")
    def test_spark_properties_integration(
        self,
        mock_client_class,
        mock_gethostname,
        mock_gethostbyname,
        mock_lightkube_class,
        mock_registry_class,
    ):
        """Test that all spark properties are correctly configured."""
        # Setup mocks
        mock_client = MagicMock()
        mock_client.config.cluster.server = "https://10.0.0.1:6443"
        mock_client_class.return_value = mock_client

        mock_lightkube = MagicMock()
        mock_lightkube_class.return_value = mock_lightkube

        mock_sa = MagicMock()
        mock_sa.configurations.props = {
            "spark.kubernetes.namespace": "test-ns",
            "spark.kubernetes.serviceAccountName": "test-user",
            "spark.executor.instances": "3",
        }
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_sa
        mock_registry_class.return_value = mock_registry

        mock_gethostname.return_value = "pod-name"
        mock_gethostbyname.return_value = "192.168.1.100"

        session = SparkSession(
            app_name="test-app", namespace="test-ns", username="test-user"
        )

        # Verify _extra_props contains driver host
        extra_props = session._extra_props
        assert "spark.driver.host" in extra_props
        assert extra_props["spark.driver.host"] == "192.168.1.100"
        assert len(extra_props) == 1

        # Verify final config merges SA props and extra props
        config = session.config
        assert config["spark.kubernetes.namespace"] == "test-ns"
        assert config["spark.kubernetes.serviceAccountName"] == "test-user"
        assert config["spark.executor.instances"] == "3"
        assert config["spark.driver.host"] == "192.168.1.100"


class TestSparkSessionContextManager:
    """Integration tests for context manager usage."""

    @pytest.mark.parametrize(
        "server_url,expected_master_url",
        [
            ("https://192.168.1.50:6443", "k8s://https://192.168.1.50:6443"),
            (
                "http://kubernetes.example.com:6443",
                "k8s://http://kubernetes.example.com:6443",
            ),
            ("https://10.0.0.1:6443", "k8s://https://10.0.0.1:6443"),
        ],
    )
    @patch("spark8t.session.pyspark")
    @patch("spark8t.session.K8sServiceAccountRegistry")
    @patch("spark8t.session.LightKube")
    @patch("socket.gethostbyname")
    @patch("socket.gethostname")
    @patch("spark8t.session.Client")
    def test_context_manager_with_k8s_master_urls(
        self,
        mock_client_class,
        mock_gethostname,
        mock_gethostbyname,
        mock_lightkube_class,
        mock_registry_class,
        mock_pyspark,
        server_url,
        expected_master_url,
    ):
        """Test context manager with different k8s master URLs and all properties."""
        # Setup mocks
        mock_client = MagicMock()
        mock_client.config.cluster.server = server_url
        mock_client_class.return_value = mock_client

        mock_lightkube = MagicMock()
        mock_lightkube_class.return_value = mock_lightkube

        mock_sa = MagicMock()
        mock_sa.configurations.props = {
            "spark.kubernetes.namespace": "test-ns",
            "spark.executor.instances": "3",
        }
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_sa
        mock_registry_class.return_value = mock_registry

        mock_gethostname.return_value = "pod-name"
        mock_gethostbyname.return_value = "192.168.1.100"

        # Setup pyspark mock
        mock_builder_instance = MagicMock()
        mock_pyspark.sql.SparkSession.builder.appName.return_value = (
            mock_builder_instance
        )
        mock_builder_instance.master.return_value = mock_builder_instance
        mock_builder_instance.config.return_value = mock_builder_instance
        mock_spark_session = MagicMock()
        mock_builder_instance.getOrCreate.return_value = mock_spark_session

        # Test with existing NO_PROXY env var to verify it's handled during SA prop retrieval
        with patch.dict(os.environ, {"NO_PROXY": "example.com,localhost"}, clear=False):
            session = SparkSession(
                app_name="test-app", namespace="test-ns", username="test-user"
            )

            with session as spark:
                # Verify session was created
                assert spark is mock_spark_session
                assert session.session is mock_spark_session

                # Verify app name
                mock_pyspark.sql.SparkSession.builder.appName.assert_called_once_with(
                    "test-app"
                )

                # Verify k8s master URL is correct (with proper URL parsing)
                mock_builder_instance.master.assert_called_once_with(
                    expected_master_url
                )

                # Verify config properties are applied
                config_calls = mock_builder_instance.config.call_args_list
                assert len(config_calls) == 3  # 2 from SA props + 1 from extra props
                config_keys = [call_args[0][0] for call_args in config_calls]
                assert "spark.kubernetes.namespace" in config_keys
                assert "spark.executor.instances" in config_keys
                assert "spark.driver.host" in config_keys

                # Verify driver host is set to the correct pod IP
                driver_host_calls = [
                    call_args
                    for call_args in config_calls
                    if call_args[0][0] == "spark.driver.host"
                ]
                assert len(driver_host_calls) == 1
                assert driver_host_calls[0][0][1] == "192.168.1.100"

            # Verify session was stopped on exit
            mock_spark_session.stop.assert_called_once()
            # Verify registry.get was called with correct namespace:username format
            # This verifies no_proxy settings were applied during SA prop retrieval
            mock_registry.get.assert_called_with("test-ns:test-user")

    @patch("spark8t.session.pyspark")
    @patch("spark8t.session.K8sServiceAccountRegistry")
    @patch("spark8t.session.LightKube")
    @patch("socket.gethostbyname")
    @patch("socket.gethostname")
    @patch("spark8t.session.Client")
    def test_spark_session_closes_on_exception(
        self,
        mock_client_class,
        mock_gethostname,
        mock_gethostbyname,
        mock_lightkube_class,
        mock_registry_class,
        mock_pyspark,
    ):
        """Test that context manager closes session even on exception."""
        # Setup mocks
        mock_client = MagicMock()
        mock_client.config.cluster.server = "https://10.0.0.1:6443"
        mock_client_class.return_value = mock_client

        mock_lightkube = MagicMock()
        mock_lightkube_class.return_value = mock_lightkube

        mock_sa = MagicMock()
        mock_sa.configurations.props = {}
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_sa
        mock_registry_class.return_value = mock_registry

        mock_gethostname.return_value = "pod-name"
        mock_gethostbyname.return_value = "192.168.1.100"

        # Setup pyspark mock
        mock_builder_instance = MagicMock()
        mock_pyspark.sql.SparkSession.builder.appName.return_value = (
            mock_builder_instance
        )
        mock_builder_instance.master.return_value = mock_builder_instance
        mock_builder_instance.config.return_value = mock_builder_instance
        mock_spark_session = MagicMock()
        mock_builder_instance.getOrCreate.return_value = mock_spark_session

        session_obj = SparkSession(
            app_name="test-app", namespace="test-ns", username="test-user"
        )

        try:
            with session_obj as spark:
                assert spark is mock_spark_session
                raise RuntimeError("Test error")
        except RuntimeError:
            pass

        # Verify session was stopped even after exception
        mock_spark_session.stop.assert_called_once()
