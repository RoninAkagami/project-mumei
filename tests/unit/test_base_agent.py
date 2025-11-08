"""
Unit tests for BaseAgent
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import os

from mumei.shared.base_agent import BaseAgent
from mumei.shared.models import Event, EventType, Priority


class TestAgent(BaseAgent):
    """Concrete implementation of BaseAgent for testing"""
    
    def run(self):
        """Implement abstract run method"""
        self.running = True


@pytest.fixture
def mock_blackboard():
    """Create a mock Blackboard"""
    blackboard = MagicMock()
    blackboard.is_connected.return_value = True
    return blackboard


@pytest.fixture
def mock_llm():
    """Create a mock LLM client"""
    llm = MagicMock()
    llm.chat.return_value = "Test response"
    return llm


@pytest.fixture
def test_agent(mock_blackboard, mock_llm):
    """Create a test agent"""
    agent = TestAgent(
        agent_id="test_agent_01",
        agent_type="test_agent",
        blackboard=mock_blackboard,
        llm_client=mock_llm
    )
    return agent


class TestBaseAgentInitialization:
    """Test BaseAgent initialization"""

    def test_initialization(self, test_agent):
        """Test agent initializes correctly"""
        assert test_agent.agent_id == "test_agent_01"
        assert test_agent.agent_type == "test_agent"
        assert test_agent.running is False
        assert test_agent.blackboard is not None
        assert test_agent.llm is not None

    def test_configuration_loading(self, test_agent):
        """Test configuration is loaded"""
        assert "log_level" in test_agent.config
        assert "timeout" in test_agent.config
        assert "max_retries" in test_agent.config


class TestBaseAgentEventPublishing:
    """Test event publishing"""

    def test_publish_event(self, test_agent, mock_blackboard):
        """Test publishing an event"""
        event = test_agent.publish_event(
            EventType.HOST_FOUND,
            data={"ip_address": "192.168.1.10"},
            priority=Priority.INFO
        )
        
        assert event.event_type == EventType.HOST_FOUND
        assert event.source_agent_id == "test_agent_01"
        assert event.priority == Priority.INFO
        assert mock_blackboard.publish.called

    def test_publish_event_with_correlation_id(self, test_agent, mock_blackboard):
        """Test publishing event with correlation ID"""
        correlation_id = "test-correlation-123"
        event = test_agent.publish_event(
            EventType.STATE_QUERY_REQUEST,
            data={},
            correlation_id=correlation_id
        )
        
        assert event.correlation_id == correlation_id

    def test_publish_multiple_events(self, test_agent, mock_blackboard):
        """Test publishing multiple events"""
        for i in range(5):
            test_agent.publish_event(
                EventType.HOST_FOUND,
                data={"index": i}
            )
        
        assert mock_blackboard.publish.call_count == 5


class TestBaseAgentEventSubscription:
    """Test event subscription"""

    def test_subscribe_to_events(self, test_agent, mock_blackboard):
        """Test subscribing to events"""
        def callback(event):
            pass
        
        test_agent.subscribe_to_events([EventType.HOST_FOUND], callback)
        
        # Subscription happens in a thread, so we just verify no errors

    def test_subscribe_to_multiple_event_types(self, test_agent, mock_blackboard):
        """Test subscribing to multiple event types"""
        def callback(event):
            pass
        
        event_types = [
            EventType.HOST_FOUND,
            EventType.SERVICE_DISCOVERED,
            EventType.VULNERABILITY_IDENTIFIED
        ]
        
        test_agent.subscribe_to_events(event_types, callback)


class TestBaseAgentCLIExecution:
    """Test CLI command execution"""

    def test_execute_cli_success(self, test_agent):
        """Test successful CLI execution"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="test output",
                stderr=""
            )
            
            result = test_agent.execute_cli("echo test")
            
            assert result["success"] is True
            assert result["returncode"] == 0
            assert result["stdout"] == "test output"
            assert "execution_time" in result

    def test_execute_cli_failure(self, test_agent):
        """Test failed CLI execution"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="error message"
            )
            
            result = test_agent.execute_cli("false")
            
            assert result["success"] is False
            assert result["returncode"] == 1
            assert result["stderr"] == "error message"

    def test_execute_cli_timeout(self, test_agent):
        """Test CLI execution timeout"""
        with patch('subprocess.run') as mock_run:
            import subprocess
            mock_run.side_effect = subprocess.TimeoutExpired("test", 10)
            
            result = test_agent.execute_cli("sleep 100", timeout=1)
            
            assert result["success"] is False
            assert "timeout" in result
            assert result["timeout"] is True

    def test_execute_cli_with_custom_timeout(self, test_agent):
        """Test CLI execution with custom timeout"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="output",
                stderr=""
            )
            
            result = test_agent.execute_cli("test command", timeout=60)
            
            # Verify timeout was passed to subprocess.run
            call_args = mock_run.call_args
            assert call_args[1]["timeout"] == 60


class TestBaseAgentStateQueries:
    """Test state query functionality"""

    def test_query_state(self, test_agent, mock_blackboard):
        """Test querying state"""
        result = test_agent.query_state("hosts", {"status": "compromised"})
        
        # Query publishes an event
        assert mock_blackboard.publish.called

    def test_query_state_with_filters(self, test_agent, mock_blackboard):
        """Test querying state with filters"""
        filters = {
            "os_type": "Linux",
            "status": "compromised"
        }
        
        result = test_agent.query_state("hosts", filters)
        
        # Verify query event was published
        assert mock_blackboard.publish.called


class TestBaseAgentLogging:
    """Test logging functionality"""

    def test_log_message(self, test_agent):
        """Test logging a message"""
        # Should not raise exception
        test_agent.log("INFO", "Test message")

    def test_log_with_context(self, test_agent):
        """Test logging with additional context"""
        test_agent.log("INFO", "Test message", extra_field="value")

    def test_log_different_levels(self, test_agent):
        """Test logging at different levels"""
        levels = ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]
        
        for level in levels:
            test_agent.log(level, f"Test {level} message")


class TestBaseAgentHeartbeat:
    """Test heartbeat functionality"""

    def test_send_heartbeat(self, test_agent, mock_blackboard):
        """Test sending heartbeat"""
        test_agent.send_heartbeat()
        
        # Heartbeat publishes an event
        assert mock_blackboard.publish.called

    def test_heartbeat_contains_agent_info(self, test_agent, mock_blackboard):
        """Test heartbeat contains agent information"""
        test_agent.send_heartbeat()
        
        # Get the published event
        call_args = mock_blackboard.publish.call_args
        event = call_args[0][1]  # Second argument is the event
        
        assert event.event_type == EventType.AGENT_HEARTBEAT
        assert event.source_agent_id == "test_agent_01"


class TestBaseAgentShutdown:
    """Test shutdown functionality"""

    def test_shutdown(self, test_agent, mock_blackboard):
        """Test graceful shutdown"""
        test_agent.running = True
        test_agent.shutdown()
        
        assert test_agent.running is False
        assert mock_blackboard.close.called

    def test_shutdown_when_not_running(self, test_agent, mock_blackboard):
        """Test shutdown when agent is not running"""
        test_agent.running = False
        test_agent.shutdown()
        
        # Should not raise exception
        assert test_agent.running is False


class TestBaseAgentConfiguration:
    """Test configuration management"""

    def test_default_configuration(self, test_agent):
        """Test default configuration values"""
        assert test_agent.config["log_level"] == "INFO"
        assert test_agent.config["timeout"] > 0
        assert test_agent.config["max_retries"] > 0

    def test_configuration_from_environment(self, monkeypatch):
        """Test loading configuration from environment"""
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("AGENT_TIMEOUT", "600")
        
        mock_blackboard = MagicMock()
        mock_llm = MagicMock()
        
        agent = TestAgent(
            agent_id="test",
            agent_type="test",
            blackboard=mock_blackboard,
            llm_client=mock_llm
        )
        
        assert agent.config["log_level"] == "DEBUG"
        assert agent.config["timeout"] == 600


class TestBaseAgentAbstractMethods:
    """Test abstract method enforcement"""

    def test_run_method_required(self):
        """Test that run() method must be implemented"""
        # TestAgent implements run(), so it should work
        mock_blackboard = MagicMock()
        mock_llm = MagicMock()
        
        agent = TestAgent(
            agent_id="test",
            agent_type="test",
            blackboard=mock_blackboard,
            llm_client=mock_llm
        )
        
        # Should have run method
        assert hasattr(agent, "run")
        assert callable(agent.run)


class TestBaseAgentIntegration:
    """Integration tests for BaseAgent"""

    def test_full_agent_lifecycle(self, test_agent, mock_blackboard):
        """Test complete agent lifecycle"""
        # Initialize
        assert test_agent.running is False
        
        # Publish event
        test_agent.publish_event(
            EventType.HOST_FOUND,
            data={"ip": "10.0.0.1"}
        )
        
        # Send heartbeat
        test_agent.send_heartbeat()
        
        # Execute command
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="output",
                stderr=""
            )
            result = test_agent.execute_cli("test")
            assert result["success"]
        
        # Shutdown
        test_agent.shutdown()
        assert test_agent.running is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
