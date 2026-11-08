import random
from collections import Counter

import pytest

from fwlens.models import Action
from fwlens.parsers.syslog import parse_lines
from fwlens.samplegen import (
    NO_TRAFFIC,
    SAMPLES,
    build_sample_logs,
    generate_events,
    render,
    sample_configs,
)

CONFIGS = {c.device: c for c in sample_configs()}


@pytest.fixture(scope="module", params=sorted(CONFIGS))
def generated(request):
    config = CONFIGS[request.param]
    rng = random.Random(7)
    pairs = generate_events(config, rng, count=300)
    return config, pairs, render(config, pairs, rng)


def test_round_trip_parse_gives_back_the_generated_events(generated, caplog) -> None:
    _, pairs, lines = generated
    assert list(parse_lines(lines)) == [event for _, event in pairs]
    # Only the deliberately truncated line is malformed; the noise line skips silently.
    assert len(caplog.records) == 1


def test_zero_hit_rules_get_no_events(generated) -> None:
    config, pairs, _ = generated
    hits = Counter(event.rule_name for _, event in pairs)
    for rule in config.rules:
        should_be_silent = not rule.enabled or not rule.log or rule.name in NO_TRAFFIC
        assert (hits[rule.name] == 0) == should_be_silent, rule.name


def test_events_match_rule_action(generated) -> None:
    _, pairs, _ = generated
    assert all(event.action is rule.action for rule, event in pairs)


def test_blocked_sessions_are_small(generated) -> None:
    _, pairs, _ = generated
    assert all(e.bytes <= 120 for _, e in pairs if e.action is not Action.ALLOW)


def test_committed_sample_logs_are_up_to_date() -> None:
    """Fails if the configs or generator changed without re-running samplegen."""
    for device, lines in build_sample_logs().items():
        committed = (SAMPLES / "logs" / f"{device}.log").read_text(encoding="utf-8")
        assert committed == "\n".join(lines) + "\n", (
            f"run: uv run python -m fwlens.samplegen ({device})"
        )
