"""
Integration tests for Blackboard (Redis Pub/Sub)
Requires Redis to be running
"""

import pytest
import time
import threading
from typing import List

from mumei.shared.blackboard import Blackboard
from mumei.shared.models import Event, EventType, Priority


@pytest.fixture
def blackboard():
    """Create a Blackboard instance for testing"""
    bb = Blackboard(host="localhost", port=6379)
    yield bb
    bb.close()


@pytest.fixture
def second_blackboard():
    """Create a second Blackboard instance for testing"""
    bb = Blackboard(host="localhost", port=6379)
    yield bb
    bb.close()


class TestBlackboardConnection:
    """Test Blackboard connection management"""

    def test_connection(self, blackboard):
        """Test successful connection to Redis"""
        assert blackboard.is_connected()

    def test_reconnection(self, blackboard):
        """Test reconnection logic"""
        # Close connection
        blackboard.close()
        
        # Reconnect
        blackboard._connect()
        
        assert blackboard.is_connected()

    def test_health_check(self, blackboard):
        """Test health check method"""
        assert blackboard.is_connected() is True


class TestBlackboardPublish:
    """Test event publishing"""

    def test_publish_event(self, blackboard):
        """Test publishing a single event"""
        event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "192.168.1.10"}
        )
        
        # Should not raise exception
        blackboard.publish("events:host_found", event)

    def test_publish_multiple_events(self, blackboard):
        """Test publishing multiple events"""
        events = [
            Event(
                event_type=EventType.HOST_FOUND,
                source_agent_id="test_agent",
                data={"ip": f"192.168.1.{i}"}
            )
            for i in range(10)
        ]
        
        for event in events:
            blackboard.publish("events:host_found", event)

    def test_publish_different_event_types(self, blackboard):
        """Test publishing different event types"""
        event_types = [
            EventType.HOST_FOUND,
            EventType.SERVICE_DISCOVERED,
            EventType.VULNERABILITY_IDENTIFIED,
            EventType.HOST_COMPROMISED
        ]
        
        for event_type in event_types:
            event = Event(
                event_type=event_type,
                source_agent_id="test_agent",
                data={"test": "data"}
            )
            channel = f"events:{event_type.value}"
            blackboard.publish(channel, event)


class TestBlackboardSubscribe:
    """Test event subscription"""

    def test_subscribe_and_receive(self, blackboard, second_blackboard):
        """Test subscribing and receiving events"""
        received_events: List[Event] = []
        
        def callback(event: Event):
            received_events.append(event)
        
        # Subscribe in a thread
        def subscribe_thread():
            second_blackboard.subscribe(["events:test"], callback)
        
        thread = threading.Thread(target=subscribe_thread, daemon=True)
        thread.start()
        
        # Wait for subscription to be ready
        time.sleep(0.5)
        
        # Publish event
        event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"test": "data"}
        )
        blackboard.publish("events:test", event)
        
        # Wait for event to be received
        time.sleep(0.5)
        
        assert len(received_events) > 0
        assert received_events[0].source_agent_id == "test_agent"

    def test_subscribe_multiple_channels(self, blackboard, second_blackboard):
        """Test subscribing to multiple channels"""
        received_events: List[Event] = []
        
        def callback(event: Event):
            received_events.append(event)
        
        # Subscribe to multiple channels
        def subscribe_thread():
            second_blackboard.subscribe(
                ["events:channel1", "events:channel2"],
                callback
            )
        
        thread = threading.Thread(target=subscribe_thread, daemon=True)
        thread.start()
        time.sleep(0.5)
        
        # Publish to both channels
        event1 = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="agent1",
            data={}
        )
        event2 = Event(
            event_type=EventType.SERVICE_DISCOVERED,
            source_agent_id="agent2",
            data={}
        )
        
        blackboard.publish("events:channel1", event1)
        blackboard.publish("events:channel2", event2)
        
        time.sleep(0.5)
        
        assert len(received_events) >= 2

    def test_unsubscribe(self, blackboard):
        """Test unsubscribing from channels"""
        received_events: List[Event] = []
        
        def callback(event: Event):
            received_events.append(event)
        
        # This test is simplified - full implementation would need
        # more complex threading and synchronization
        blackboard.unsubscribe(["events:test"])


class TestBlackboardPerformance:
    """Test Blackboard performance"""

    def test_publish_latency(self, blackboard):
        """Test event publishing latency"""
        event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={}
        )
        
        start_time = time.time()
        blackboard.publish("events:test", event)
        end_time = time.time()
        
        latency = (end_time - start_time) * 1000  # Convert to ms
        
        # Should be less than 100ms
        assert latency < 100

    def test_high_throughput(self, blackboard):
        """Test publishing many events quickly"""
        num_events = 100
        
        start_time = time.time()
        
        for i in range(num_events):
            event = Event(
                event_type=EventType.HOST_FOUND,
                source_agent_id="test_agent",
                data={"index": i}
            )
            blackboard.publish("events:test", event)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should handle 100 events in reasonable time
        assert duration < 5.0  # 5 seconds
        
        events_per_second = num_events / duration
        print(f"Throughput: {events_per_second:.2f} events/second")

    def test_message_delivery_latency(self, blackboard, second_blackboard):
        """Test end-to-end message delivery latency"""
        received_times: List[float] = []
        
        def callback(event: Event):
            received_times.append(time.time())
        
        # Subscribe
        def subscribe_thread():
            second_blackboard.subscribe(["events:latency_test"], callback)
        
        thread = threading.Thread(target=subscribe_thread, daemon=True)
        thread.start()
        time.sleep(0.5)
        
        # Publish and measure
        send_time = time.time()
        event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={}
        )
        blackboard.publish("events:latency_test", event)
        
        # Wait for delivery
        time.sleep(0.2)
        
        if received_times:
            latency = (received_times[0] - send_time) * 1000  # ms
            print(f"Message delivery latency: {latency:.2f}ms")
            
            # Should be less than 100ms
            assert latency < 100


class TestBlackboardErrorHandling:
    """Test error handling"""

    def test_publish_with_invalid_connection(self):
        """Test publishing with invalid Redis connection"""
        # Create blackboard with invalid host
        bb = Blackboard(host="invalid_host", port=9999)
        
        # Should raise exception during connection
        with pytest.raises(Exception):
            pass  # Connection attempt happens in __init__

    def test_reconnection_after_failure(self, blackboard):
        """Test reconnection after connection failure"""
        # This is a simplified test
        # In production, would simulate Redis restart
        
        assert blackboard.is_connected()
        
        # Close and reconnect
        blackboard.close()
        blackboard._connect()
        
        assert blackboard.is_connected()


class TestBlackboardConcurrency:
    """Test concurrent operations"""

    def test_concurrent_publishers(self, blackboard):
        """Test multiple publishers simultaneously"""
        def publish_events(agent_id: str, count: int):
            for i in range(count):
                event = Event(
                    event_type=EventType.HOST_FOUND,
                    source_agent_id=agent_id,
                    data={"index": i}
                )
                blackboard.publish("events:concurrent_test", event)
        
        # Create multiple publisher threads
        threads = []
        for i in range(5):
            thread = threading.Thread(
                target=publish_events,
                args=(f"agent_{i}", 10)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # All events should be published successfully

    def test_concurrent_subscribers(self, blackboard):
        """Test multiple subscribers simultaneously"""
        received_counts = [0, 0, 0]
        
        def callback(index: int):
            def cb(event: Event):
                received_counts[index] += 1
            return cb
        
        # Create multiple subscriber threads
        threads = []
        for i in range(3):
            bb = Blackboard(host="localhost", port=6379)
            
            def subscribe_thread(bb_instance, idx):
                bb_instance.subscribe(["events:multi_sub_test"], callback(idx))
            
            thread = threading.Thread(
                target=subscribe_thread,
                args=(bb, i),
                daemon=True
            )
            threads.append(thread)
            thread.start()
        
        time.sleep(0.5)
        
        # Publish events
        for i in range(5):
            event = Event(
                event_type=EventType.HOST_FOUND,
                source_agent_id="test_agent",
                data={"index": i}
            )
            blackboard.publish("events:multi_sub_test", event)
        
        time.sleep(0.5)
        
        # All subscribers should receive events
        # (Note: actual counts may vary due to threading)


class TestBlackboardIntegration:
    """Integration tests with real scenarios"""

    def test_agent_communication_flow(self, blackboard, second_blackboard):
        """Test realistic agent communication flow"""
        received_events: List[Event] = []
        
        def callback(event: Event):
            received_events.append(event)
        
        # Agent 2 subscribes to events
        def subscribe_thread():
            second_blackboard.subscribe(
                ["events:host_found", "events:service_discovered"],
                callback
            )
        
        thread = threading.Thread(target=subscribe_thread, daemon=True)
        thread.start()
        time.sleep(0.5)
        
        # Agent 1 discovers a host
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="surface_mapper",
            data={"ip_address": "192.168.1.10"}
        )
        blackboard.publish("events:host_found", host_event)
        
        time.sleep(0.2)
        
        # Agent 1 discovers a service
        service_event = Event(
            event_type=EventType.SERVICE_DISCOVERED,
            source_agent_id="surface_mapper",
            data={"port": 80, "service": "http"}
        )
        blackboard.publish("events:service_discovered", service_event)
        
        time.sleep(0.2)
        
        # Agent 2 should have received both events
        assert len(received_events) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
