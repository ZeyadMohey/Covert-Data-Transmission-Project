"""Unit tests for sender.py orchestration (channels mocked, no network I/O)."""

import multiprocessing
from unittest.mock import patch, MagicMock, call
import pytest


def test_channel_timeout_exists_and_positive():
    from lib.config import CHANNEL_TIMEOUT
    assert isinstance(CHANNEL_TIMEOUT, int)
    assert CHANNEL_TIMEOUT > 0


def test_ack_timeout_exists_and_positive():
    from lib.config import ACK_TIMEOUT
    assert isinstance(ACK_TIMEOUT, int)
    assert ACK_TIMEOUT > 0


def test_channel_worker_success():
    from sender import _channel_worker

    def mock_target(a, b):
        return a + b

    q = multiprocessing.Queue()
    _channel_worker(mock_target, (3, 4), q, "ARP")
    status, name, result = q.get(timeout=5)
    assert status == "ok"
    assert name == "ARP"
    assert result == 7


def test_channel_worker_error():
    from sender import _channel_worker

    def failing_target():
        raise RuntimeError("timeout reached")

    q = multiprocessing.Queue()
    _channel_worker(failing_target, (), q, "MTNS")
    status, name, err = q.get(timeout=5)
    assert status == "error"
    assert name == "MTNS"
    assert "timeout reached" in err


def test_channel_worker_none_return():
    from sender import _channel_worker

    def void_target():
        pass

    q = multiprocessing.Queue()
    _channel_worker(void_target, (), q, "ARP")
    status, name, result = q.get(timeout=5)
    assert status == "ok"
    assert name == "ARP"
    assert result is None


def test_share_division_arp_gets_first_two():
    from lib.config import ARP_SHARES_COUNT
    hashed = [f"{i}-abc{i}hash" for i in range(1, 8)]
    arp_shares = hashed[:ARP_SHARES_COUNT]
    assert len(arp_shares) == 2
    assert arp_shares == ["1-abc1hash", "2-abc2hash"]


def test_share_division_mtns_gets_remaining():
    from lib.config import ARP_SHARES_COUNT
    hashed = [f"{i}-abc{i}hash" for i in range(1, 8)]
    mtns_shares = hashed[ARP_SHARES_COUNT:]
    assert len(mtns_shares) == 5
    assert mtns_shares[0] == "3-abc3hash"


def test_share_join_with_separator():
    from lib.config import SEPARATOR
    shares = ["1-abchash", "2-defhash"]
    joined = SEPARATOR.join(shares)
    assert joined == "1-abchash|2-defhash"


@patch("sender.mtns_send")
@patch("sender.arp_send")
@patch("sender.append_hash", side_effect=lambda s: s + "hashbits")
@patch("sender.split_secret", return_value=[f"{i}-share{i}" for i in range(1, 8)])
@patch("builtins.input", side_effect=["Attack at dawn", ""])
def test_sender_logging_secret_message(mock_input, mock_split, mock_hash,
                                        mock_arp, mock_mtns, capsys):
    from sender import main
    with patch("sender.multiprocessing"):
        try:
            main()
        except (SystemExit, Exception):
            pass
    captured = capsys.readouterr().out
    assert "[SENDER] Secret message: Attack at dawn" in captured


@patch("sender.mtns_send")
@patch("sender.arp_send")
@patch("sender.append_hash", side_effect=lambda s: s + "hashbits")
@patch("sender.split_secret", return_value=[f"{i}-share{i}" for i in range(1, 8)])
@patch("builtins.input", side_effect=["Attack at dawn", ""])
def test_sender_logging_generating_shares(mock_input, mock_split, mock_hash,
                                           mock_arp, mock_mtns, capsys):
    from sender import main
    with patch("sender.multiprocessing"):
        try:
            main()
        except (SystemExit, Exception):
            pass
    captured = capsys.readouterr().out
    assert "[SENDER] Generating 7 shares" in captured


@patch("sender.mtns_send")
@patch("sender.arp_send")
@patch("sender.append_hash", side_effect=lambda s: s + "hashbits")
@patch("sender.split_secret", return_value=[f"{i}-share{i}" for i in range(1, 8)])
@patch("builtins.input", side_effect=["Attack at dawn", ""])
def test_sender_logging_arp_channel(mock_input, mock_split, mock_hash,
                                     mock_arp, mock_mtns, capsys):
    from sender import main
    with patch("sender.multiprocessing"):
        try:
            main()
        except (SystemExit, Exception):
            pass
    captured = capsys.readouterr().out
    assert "[SENDER] Sending 2 shares via ARP channel" in captured


@patch("sender.mtns_send")
@patch("sender.arp_send")
@patch("sender.append_hash", side_effect=lambda s: s + "hashbits")
@patch("sender.split_secret", return_value=[f"{i}-share{i}" for i in range(1, 8)])
@patch("builtins.input", side_effect=["Attack at dawn", ""])
def test_sender_logging_mtns_channel(mock_input, mock_split, mock_hash,
                                      mock_arp, mock_mtns, capsys):
    from sender import main
    with patch("sender.multiprocessing"):
        try:
            main()
        except (SystemExit, Exception):
            pass
    captured = capsys.readouterr().out
    assert "[SENDER] Sending 5 shares via MTNS channel" in captured


def test_ack_listener_puts_true_on_packet():
    from sender import _ack_listener

    q = multiprocessing.Queue()
    with patch("sender._sniff_ack", return_value=[MagicMock()]):
        _ack_listener(q, "192.168.100.6", 9999, "enp0s9", 30)
    assert q.get(timeout=5) is True


def test_ack_listener_puts_false_on_timeout():
    from sender import _ack_listener

    q = multiprocessing.Queue()
    with patch("sender._sniff_ack", return_value=[]):
        _ack_listener(q, "192.168.100.6", 9999, "enp0s9", 30)
    assert q.get(timeout=5) is False


def test_channel_worker_exception_gives_error_tuple():
    from sender import _channel_worker

    def bad_func(x):
        raise ValueError("bad value")

    q = multiprocessing.Queue()
    _channel_worker(bad_func, (42,), q, "ARP")
    status, name, err = q.get(timeout=5)
    assert status == "error"
    assert name == "ARP"
    assert "bad value" in err


@patch("builtins.input", return_value="")
def test_empty_message_rejected(mock_input, capsys):
    from sender import main
    with pytest.raises(SystemExit):
        main()
    captured = capsys.readouterr().out
    assert "Message cannot be empty" in captured
