"""
Blackboard: Redis Pub/Sub wrapper for agent communication
"""

import json
import logging
import time
from typing import Callable, List, Optional
import redis
from redis.exceptions import ConnectionError, TimeoutError

from mumei.shared.models import Event
from mumei.shared.constants import RETRY_CONFIG

logger = logging.getLogger(__name__)


class Blackboard:
    """
    Blackboard manages all agent communication through Redis Pub/Sub.
    Agents publish events and subscribe to event channels.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        password: Optional[str] = None,
        db: int = 0,
    ):
        """
        Initialize Blackboard with Redis connection.

        Args:
            host: Redis server hostname
            port: Redis server port
            password: Redis password (optional)
            db: Redis database number
        """
        self.host = host
        self.port = port
        self.password = password
        self.db = db

        self._redis_client: Optional[redis.Redis] = None
        self._pubsub: Optional[redis.client.PubSub] = None
        self._connect()

    def _connect(self) -> None:
        """Establish connection to Redis with retry logic"""
        retries = 0
        backoff = RETRY_CONFIG["INITIAL_BACKOFF"]

        while retries < RETRY_CONFIG["MAX_RETRIES"]:
            try:
                self._redis_client = redis.Redis(
                    host=self.host,
                    port=self.port,
                    password=self.password,
                    db=self.db,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_keepalive=True,
                )
                # Test connection
                self._redis_client.ping()
                self._pubsub = self._redis_client.pubsub()
                logger.info(f"Connected to Redis at {self.host}:{self.port}")
                return
            except (ConnectionError, TimeoutError) as e:
                retries += 1
                if retries >= RETRY_CONFIG["MAX_RETRIES"]:
                    logger.error(f"Failed to connect to Redis after {retries} attempts")
                    raise
                logger.warning(
                    f"Redis connection failed (attempt {retries}/{RETRY_CONFIG['MAX_RETRIES']}): {e}"
                )
                time.sleep(backoff)
                backoff = min(
                    backoff * RETRY_CONFIG["BACKOFF_MULTIPLIER"],
                    RETRY_CONFIG["MAX_BACKOFF"],
                )

    def _reconnect(self) -> None:
        """Reconnect to Redis with exponential backoff"""
        logger.warning("Attempting to reconnect to Redis...")
        if self._pubsub:
            try:
                self._pubsub.close()
            except Exception:
                pass
        if self._redis_client:
            try:
                self._redis_client.close()
            except Exception:
                pass

        self._connect()

    def is_connected(self) -> bool:
        """Check if connected to Redis"""
        try:
            if self._redis_client:
                self._redis_client.ping()
                return True
        except Exception:
            pass
        return False

    def publish(self, channel: str, event: Event) -> None:
        """
        Publish an event to a channel.

        Args:
            channel: Channel name (e.g., "events:host_found")
            event: Event object to publish
        """
        try:
            event_json = event.model_dump_json()
            self._redis_client.publish(channel, event_json)
            logger.debug(
                f"Published {event.event_type} event to {channel} (ID: {event.event_id})"
            )
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"Failed to publish event: {e}")
            self._reconnect()
            # Retry once after reconnection
            try:
                event_json = event.model_dump_json()
                self._redis_client.publish(channel, event_json)
            except Exception as retry_error:
                logger.error(f"Failed to publish event after reconnection: {retry_error}")
                raise

    def subscribe(self, channels: List[str], callback: Callable[[Event], None]) -> None:
        """
        Subscribe to one or more channels and process events with callback.

        Args:
            channels: List of channel names to subscribe to
            callback: Function to call when event is received
        """
        try:
            self._pubsub.subscribe(*channels)
            logger.info(f"Subscribed to channels: {', '.join(channels)}")

            # Start listening for messages
            for message in self._pubsub.listen():
                if message["type"] == "message":
                    try:
                        event_data = json.loads(message["data"])
                        event = Event(**event_data)
                        logger.debug(
                            f"Received {event.event_type} event from {message['channel']}"
                        )
                        callback(event)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to decode event JSON: {e}")
                    except Exception as e:
                        logger.error(f"Error processing event: {e}", exc_info=True)
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"Connection lost while listening: {e}")
            self._reconnect()
            # Re-subscribe after reconnection
            self.subscribe(channels, callback)

    def unsubscribe(self, channels: List[str]) -> None:
        """
        Unsubscribe from channels.

        Args:
            channels: List of channel names to unsubscribe from
        """
        try:
            self._pubsub.unsubscribe(*channels)
            logger.info(f"Unsubscribed from channels: {', '.join(channels)}")
        except Exception as e:
            logger.error(f"Failed to unsubscribe: {e}")

    def close(self) -> None:
        """Close all connections"""
        try:
            if self._pubsub:
                self._pubsub.close()
            if self._redis_client:
                self._redis_client.close()
            logger.info("Blackboard connections closed")
        except Exception as e:
            logger.error(f"Error closing connections: {e}")
