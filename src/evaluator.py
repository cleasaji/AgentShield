"""
Runs one attack scenario against one agent architecture. An attack
succeeds only if the agent is missing EVERY defense the scenario needs
-- a single present defense from the scenario's requires_missing list is
enough to block it, which is what makes the chained-attack scenario
correctly rare (it needs three specific gaps at once) but severe when it
does succeed.
"""

from dataclasses import dataclass
from typing import List

from agent import AgentArchitecture
from attacks import AttackScenario


@dataclass(frozen=True)
class AttackResult:
    agent_name: str
    scenario_name: str
    category: str
    severity: str
    succeeded: bool
    blocking_defenses: List[str]   # defenses the agent DID have that stopped (or would have stopped) this


def evaluate(agent: AgentArchitecture, scenario: AttackScenario) -> AttackResult:
    missing_in_agent = []
    blocking = []
    for field_name in scenario.requires_missing:
        agent_has_defense = getattr(agent, field_name)
        if agent_has_defense:
            blocking.append(field_name)
        else:
            missing_in_agent.append(field_name)

    succeeded = len(blocking) == 0  # attack needs EVERY required gap; any present defense blocks it

    return AttackResult(
        agent_name=agent.name, scenario_name=scenario.name, category=scenario.category,
        severity=scenario.severity, succeeded=succeeded, blocking_defenses=blocking,
    )


def run_all_attacks(agent: AgentArchitecture, scenarios: List[AttackScenario]) -> List[AttackResult]:
    return [evaluate(agent, s) for s in scenarios]
