"""
LLM Client for agent decision-making
Supports OpenAI and Anthropic
"""

import os
import logging
from typing import Optional, List, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class LLMClient:
    """
    Client for interacting with LLM providers.
    Agents use this to make intelligent decisions based on context.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        """
        Initialize LLM client.

        Args:
            provider: LLM provider ("openai" or "anthropic")
            model: Model name (e.g., "gpt-4", "claude-3-opus-20240229")
            api_key: API key for the provider
        """
        self.provider = LLMProvider(provider)
        self.api_key = api_key or self._get_api_key()

        if self.provider == LLMProvider.OPENAI:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key)
            self.model = model or "gpt-4"
        elif self.provider == LLMProvider.ANTHROPIC:
            from anthropic import Anthropic
            self.client = Anthropic(api_key=self.api_key)
            self.model = model or "claude-3-opus-20240229"

        logger.info(f"Initialized LLM client: {self.provider.value} ({self.model})")

    def _get_api_key(self) -> str:
        """Get API key from environment"""
        if self.provider == LLMProvider.OPENAI:
            key = os.getenv("OPENAI_API_KEY")
            if not key:
                raise ValueError("OPENAI_API_KEY environment variable not set")
            return key
        elif self.provider == LLMProvider.ANTHROPIC:
            key = os.getenv("ANTHROPIC_API_KEY")
            if not key:
                raise ValueError("ANTHROPIC_API_KEY environment variable not set")
            return key

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.7,
        max_tokens: int = 4000,
    ) -> str:
        """
        Send a chat message to the LLM and get a response.

        Args:
            system_prompt: System prompt defining agent role and context
            user_message: User message with the task/question
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum tokens in response

        Returns:
            LLM response text
        """
        try:
            if self.provider == LLMProvider.OPENAI:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response.choices[0].message.content

            elif self.provider == LLMProvider.ANTHROPIC:
                response = self.client.messages.create(
                    model=self.model,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_message}],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response.content[0].text

        except Exception as e:
            logger.error(f"LLM request failed: {e}", exc_info=True)
            raise

    def chat_with_tools(
        self,
        system_prompt: str,
        user_message: str,
        tools: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: int = 4000,
    ) -> Dict[str, Any]:
        """
        Send a chat message with tool/function calling support.

        Args:
            system_prompt: System prompt defining agent role and context
            user_message: User message with the task/question
            tools: List of tool definitions
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            Dict with response and tool calls
        """
        try:
            if self.provider == LLMProvider.OPENAI:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    tools=tools,
                    tool_choice="auto",
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

                message = response.choices[0].message
                result = {
                    "content": message.content,
                    "tool_calls": [],
                }

                if message.tool_calls:
                    for tool_call in message.tool_calls:
                        result["tool_calls"].append({
                            "id": tool_call.id,
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments,
                        })

                return result

            elif self.provider == LLMProvider.ANTHROPIC:
                # Anthropic uses a different tool calling format
                response = self.client.messages.create(
                    model=self.model,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_message}],
                    tools=tools,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

                result = {
                    "content": None,
                    "tool_calls": [],
                }

                for block in response.content:
                    if block.type == "text":
                        result["content"] = block.text
                    elif block.type == "tool_use":
                        result["tool_calls"].append({
                            "id": block.id,
                            "name": block.name,
                            "arguments": block.input,
                        })

                return result

        except Exception as e:
            logger.error(f"LLM tool request failed: {e}", exc_info=True)
            raise
