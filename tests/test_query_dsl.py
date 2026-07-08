from engine.query_dsl import parse_query

FIELDS = {
    "ip": "source_ip", "source_ip": "source_ip",
    "user": "username", "username": "username",
    "port": "source_port",
}
NUMERIC = {"source_port"}


def test_empty_query_returns_no_clause():
    assert parse_query("", FIELDS, "raw_line") == ("", ())
    assert parse_query(None, FIELDS, "raw_line") == ("", ())


def test_free_text_searches_free_text_column():
    clause, params = parse_query("connection refused", FIELDS, "raw_line")

    assert "raw_line" in clause
    assert params == ("%connection%", "%refused%")


def test_field_value_maps_to_real_column():
    clause, params = parse_query("ip:203.0.113.9", FIELDS, "raw_line")

    assert "source_ip" in clause
    assert params == ("%203.0.113.9%",)


def test_unknown_field_falls_back_to_free_text():
    clause, params = parse_query("nope:whatever", FIELDS, "raw_line")

    assert "raw_line" in clause
    assert params == ("%nope:whatever%",)


def test_numeric_field_uses_exact_match():
    clause, params = parse_query("port:22", FIELDS, "raw_line", NUMERIC)

    assert "source_port = ?" in clause
    assert params == ("22",)


def test_and_combines_two_conditions():
    clause, params = parse_query("ip:1.2.3.4 AND user:root", FIELDS, "raw_line")

    assert " AND " in clause
    assert params == ("%1.2.3.4%", "%root%")


def test_or_combines_two_conditions():
    clause, params = parse_query("user:root OR user:admin", FIELDS, "raw_line")

    assert " OR " in clause
    assert params == ("%root%", "%admin%")


def test_not_negates_condition():
    clause, params = parse_query("NOT user:root", FIELDS, "raw_line")

    assert "NOT (LOWER(username) LIKE ?)" in clause
    assert params == ("%root%",)


def test_quoted_phrase_kept_as_single_token():
    clause, params = parse_query('"login denied"', FIELDS, "raw_line")

    assert params == ("%login denied%",)


def test_case_insensitive_field_name():
    clause, params = parse_query("IP:1.2.3.4", FIELDS, "raw_line")

    assert "source_ip" in clause
    assert params == ("%1.2.3.4%",)


def test_left_to_right_folding_with_mixed_connectors():
    clause, _params = parse_query("user:a OR user:b AND user:c", FIELDS, "raw_line")

    # se pliega como ((a OR b) AND c), no con precedencia AND-antes-que-OR
    assert clause.count("(") == clause.count(")")
    assert clause.index(" OR ") < clause.index(" AND ")
