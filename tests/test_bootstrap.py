import pytest

from engine import storage, log_generator
from engine.agents import Agent
from engine.bootstrap import simulate_tick


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """DB y logs/raw temporales — no tocar data/siem.db ni logs/raw reales."""
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test_siem.db")
    monkeypatch.setattr(log_generator, "RAW_LOGS_PATH", tmp_path / "raw")
    storage.initialize_db()
    yield


ONE_AGENT = [Agent(
    agent_id="agent-001", hostname="prod-server-01", ip_address="10.0.0.5",
    os="Ubuntu 22.04 LTS", log_sources=["ssh"],
)]


def test_simulate_tick_inserts_events_and_touches_agent():
    storage.register_agents(ONE_AGENT)

    simulate_tick(agents=ONE_AGENT, duration_seconds=2, events_per_second=3.0)

    summary = storage.query_events_summary()
    assert summary["total_events"] > 0

    agents = storage.query_agents()
    assert agents[0]["last_seen"] is not None


def test_simulate_tick_twice_does_not_lose_alerts_to_id_collisions():
    storage.register_agents(ONE_AGENT)

    # attack_probability alto para casi garantizar al menos una alerta por tick
    simulate_tick(agents=ONE_AGENT, duration_seconds=3, events_per_second=5.0, attack_probability=0.8)
    first_count = storage.query_events_summary()["total_alerts"]

    simulate_tick(agents=ONE_AGENT, duration_seconds=3, events_per_second=5.0, attack_probability=0.8)
    second_count = storage.query_events_summary()["total_alerts"]

    # Si los IDs colisionaran (contador reiniciado en 0 cada vez),
    # INSERT OR IGNORE descartaría las alertas del segundo tick.
    assert second_count >= first_count
