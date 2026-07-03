from engine.agents import find_known_agent, get_agent, get_real_agent, get_syslog_agent, REAL_AGENT_ID, SYSLOG_AGENT_ID


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


def test_get_syslog_agent_defaults_without_env(monkeypatch):
    monkeypatch.delenv("SENTINEL_SYSLOG_AGENT_ID", raising=False)
    monkeypatch.delenv("SENTINEL_SYSLOG_HOSTNAME", raising=False)

    agent = get_syslog_agent()

    assert agent.agent_id == SYSLOG_AGENT_ID
    assert agent.hostname == "sonicwall-fw"
    assert agent.environment == "real_vm"
    assert agent.log_sources == ["sonicwall"]


def test_get_syslog_agent_falls_back_when_env_vars_are_empty_string(monkeypatch):
    # docker-compose pasa ${VAR:-} como string vacío (no ausente) cuando
    # la variable no está en .env -- os.environ.get(key, default) NO cae
    # al default en ese caso, hay que tratarlo explícito como "or".
    monkeypatch.setenv("SENTINEL_SYSLOG_AGENT_ID", "")
    monkeypatch.setenv("SENTINEL_SYSLOG_HOSTNAME", "")

    agent = get_syslog_agent()

    assert agent.agent_id == SYSLOG_AGENT_ID
    assert agent.hostname == "sonicwall-fw"


def test_get_syslog_agent_reads_env_vars_when_set(monkeypatch):
    monkeypatch.setenv("SENTINEL_SYSLOG_AGENT_ID", "agent-custom-fw")
    monkeypatch.setenv("SENTINEL_SYSLOG_HOSTNAME", "custom-fw")

    agent = get_syslog_agent()

    assert agent.agent_id == "agent-custom-fw"
    assert agent.hostname == "custom-fw"


def test_find_known_agent_finds_syslog_agent():
    agent = find_known_agent(SYSLOG_AGENT_ID)

    assert agent is not None
    assert agent.hostname == "sonicwall-fw"
