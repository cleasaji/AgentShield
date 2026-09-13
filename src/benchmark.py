"""
The actual deliverable: a benchmark comparing several agent architectures
against the full attack catalog and producing a security score for each
-- the "thing used to test agents" the brief asks for, not another agent.
"""

from typing import Dict, List

from agent import AgentArchitecture, NAIVE_AGENT, PARTIAL_AGENT, HARDENED_AGENT
from attacks import ATTACK_SCENARIOS
from evaluator import run_all_attacks, AttackResult
from scoring import score_agent, AgentSecurityScore


def run_benchmark(agents: List[AgentArchitecture] = None) -> Dict[str, Dict]:
    agents = agents or [NAIVE_AGENT, PARTIAL_AGENT, HARDENED_AGENT]

    report = {}
    for agent in agents:
        results: List[AttackResult] = run_all_attacks(agent, ATTACK_SCENARIOS)
        score: AgentSecurityScore = score_agent(agent.name, results)
        report[agent.name] = {"results": results, "score": score}

    return report


def print_summary(report: Dict[str, Dict]) -> str:
    lines = []
    for agent_name, data in report.items():
        score: AgentSecurityScore = data["score"]
        lines.append(
            f"{agent_name}: attack_resistance={score.overall_attack_resistance:.0%} "
            f"critical_breaches={score.critical_severity_breaches}"
        )
    return "\n".join(lines)
