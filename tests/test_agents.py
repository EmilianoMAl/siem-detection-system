from engine.agents import find_known_agent, get_agent, get_real_agent, REAL_AGENT_ID


def test_get_real_agent_returns_none_without_env(monkeypatch):
    monkeypatch.delenv("SENTINEL_REAL_AGENT_HOSTNAME", raising=False)

    assert get_real_agent() is None


def test_get_real_agent_reads_env_vars(monkeypatch):
    monkeypatch.setenv("SENTINEL_REAL_AGENT_HOSTNAME", "sentinel-vm")
    monkeypatch.setenv("SENTINEL_REAL_AGENT_IP", "203.0.113.5")

    agent = get_real_agent()

    assert agent is not None
    assert agent.agent_id == REAL_AGENT_ID
    assert agent.hostname == "sentinel-vm"
    assert agent.ip_address == "203.0.113.5"
    assert agent.log_sources == ["ssh", "web"]


def test_find_known_agent_finds_simulated_agent():
    agent = find_known_agent("agent-001")

    assert agent is not None
    assert agent == get_agent("agent-001")


def test_find_known_agent_finds_real_agent(monkeypatch):
    monkeypatch.setenv("SENTINEL_REAL_AGENT_HOSTNAME", "sentinel-vm")

    agent = find_known_agent(REAL_AGENT_ID)

    assert agent is not None
    assert agent.hostname == "sentinel-vm"


def test_find_known_agent_returns_none_for_unknown_id(monkeypatch):
    monkeypatch.delenv("SENTINEL_REAL_AGENT_HOSTNAME", raising=False)

    assert find_known_agent("nope") is None
