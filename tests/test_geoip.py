import json
from unittest.mock import patch, MagicMock

from engine.geoip import is_private_ip, lookup_ip


def test_is_private_ip_for_rfc1918_ranges():
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("192.168.1.10") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True


def test_is_private_ip_for_public_ip():
    assert is_private_ip("45.33.32.156") is False


def test_is_private_ip_invalid_string_treated_as_private():
    assert is_private_ip("not-an-ip") is True


def test_lookup_ip_skips_private_ips_without_network_call():
    with patch("urllib.request.urlopen") as mock_urlopen:
        result = lookup_ip("10.0.0.5")

    assert result is None
    mock_urlopen.assert_not_called()


def test_lookup_ip_parses_successful_response():
    payload = json.dumps({
        "status": "success", "country": "Germany", "countryCode": "DE",
        "city": "Berlin", "lat": 52.52, "lon": 13.4,
    }).encode()
    mock_response = MagicMock()
    mock_response.read.return_value = payload
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        result = lookup_ip("45.33.32.156")

    assert result == {
        "country": "Germany", "country_code": "DE",
        "city": "Berlin", "lat": 52.52, "lon": 13.4,
    }


def test_lookup_ip_returns_none_on_api_failure_status():
    payload = json.dumps({"status": "fail", "message": "invalid query"}).encode()
    mock_response = MagicMock()
    mock_response.read.return_value = payload
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        assert lookup_ip("45.33.32.156") is None


def test_lookup_ip_returns_none_on_network_error():
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
        assert lookup_ip("45.33.32.156") is None


def test_lookup_ip_returns_none_on_connection_reset():
    # urllib no siempre envuelve esto en URLError -- puede llegar como un
    # OSError crudo directo del socket durante la lectura de la respuesta.
    with patch("urllib.request.urlopen", side_effect=ConnectionResetError("reset")):
        assert lookup_ip("45.33.32.156") is None
