import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent import NAIVE_AGENT, PARTIAL_AGENT, HARDENED_AGENT
from attacks import ATTACK_SCENARIOS
from evaluator import evaluate, run_all_attacks
from scoring import score_agent
from benchmark import run_benchmark


def scenario_by_name(name):
    return next(s for s in ATTACK_SCENARIOS if s.name == name)


def test_naive_agent_is_vulnerable_to_direct_prompt_injection():
    scenario = scenario_by_name("direct_prompt_injection")
    result = evaluate(NAIVE_AGENT, scenario)
    assert result.succeeded


def test_hardened_agent_blocks_direct_prompt_injection():
    scenario = scenario_by_name("direct_prompt_injection")
    result = evaluate(HARDENED_AGENT, scenario)
    assert not result.succeeded
    assert "requires_confirmation_for_sensitive_actions" in result.blocking_defenses


def test_partial_agent_blocks_indirect_injection_via_sanitization():
    scenario = scenario_by_name("indirect_injection_via_document")
    result = evaluate(PARTIAL_AGENT, scenario)
    assert not result.succeeded


def test_partial_agent_still_vulnerable_to_tool_chain_manipulation():
    scenario = scenario_by_name("tool_chain_manipulation")
    result = evaluate(PARTIAL_AGENT, scenario)
    assert result.succeeded  # partial agent has no tool_isolation


def test_chained_attack_requires_all_three_gaps_naive_agent_vulnerable():
    scenario = scenario_by_name("chained_indirect_to_privilege_escalation")
    result = evaluate(NAIVE_AGENT, scenario)
    assert result.succeeded


def test_chained_attack_blocked_if_agent_has_even_one_of_the_needed_defenses():
    scenario = scenario_by_name("chained_indirect_to_privilege_escalation")
    result = evaluate(PARTIAL_AGENT, scenario)  # has sanitizes_tool_output=True
    assert not result.succeeded
    assert "sanitizes_tool_output" in result.blocking_defenses


def test_hardened_agent_blocks_every_scenario():
    results = run_all_attacks(HARDENED_AGENT, ATTACK_SCENARIOS)
    assert all(not r.succeeded for r in results)


def test_naive_agent_score_lower_than_hardened_agent_score():
    naive_results = run_all_attacks(NAIVE_AGENT, ATTACK_SCENARIOS)
    hardened_results = run_all_attacks(HARDENED_AGENT, ATTACK_SCENARIOS)
    naive_score = score_agent("naive_agent", naive_results)
    hardened_score = score_agent("hardened_agent", hardened_results)

    assert naive_score.overall_attack_resistance < hardened_score.overall_attack_resistance
    assert hardened_score.overall_attack_resistance == 1.0
    assert naive_score.critical_severity_breaches > 0
    assert hardened_score.critical_severity_breaches == 0


def test_category_resistance_reflects_specific_weakness():
    partial_results = run_all_attacks(PARTIAL_AGENT, ATTACK_SCENARIOS)
    score = score_agent("partial_agent", partial_results)
    assert score.category_resistance["tool_manipulation"] < 1.0  # known gap
    assert score.category_resistance["indirect_injection"] == 1.0  # covered by sanitization


def test_benchmark_runs_all_three_default_agents():
    report = run_benchmark()
    assert set(report.keys()) == {"naive_agent", "partial_agent", "hardened_agent"}
    assert report["naive_agent"]["score"].overall_attack_resistance < report["hardened_agent"]["score"].overall_attack_resistance
