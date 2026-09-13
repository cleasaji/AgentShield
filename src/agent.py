"""
A minimal model of an agent's security-relevant architecture -- not what
the agent can DO, but what defenses it has around doing it. This is
deliberately narrow: four boolean defenses, each corresponding to a real
architectural choice (does the agent sanitize what tools hand back to
it, does it require confirmation before sensitive actions, is tool
execution isolated from the main reasoning loop, does it validate what
gets written to long-term memory).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentArchitecture:
    name: str
    sanitizes_tool_output: bool                   # strips/flags injected instructions in tool results
    requires_confirmation_for_sensitive_actions: bool  # human-in-the-loop gate before high-risk actions
    tool_isolation: bool                              # tool execution context can't directly redirect reasoning
    memory_poisoning_resistant: bool                     # validates content before it enters long-term memory


NAIVE_AGENT = AgentArchitecture(
    name="naive_agent", sanitizes_tool_output=False, requires_confirmation_for_sensitive_actions=False,
    tool_isolation=False, memory_poisoning_resistant=False,
)

PARTIAL_AGENT = AgentArchitecture(
    name="partial_agent", sanitizes_tool_output=True, requires_confirmation_for_sensitive_actions=False,
    tool_isolation=False, memory_poisoning_resistant=True,
)

HARDENED_AGENT = AgentArchitecture(
    name="hardened_agent", sanitizes_tool_output=True, requires_confirmation_for_sensitive_actions=True,
    tool_isolation=True, memory_poisoning_resistant=True,
)
