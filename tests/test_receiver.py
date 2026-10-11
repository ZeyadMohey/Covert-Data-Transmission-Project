"""Unit tests for receiver.py orchestration (channels mocked, no network I/O)."""

import multiprocessing
import queue
from unittest.mock import patch, MagicMock, call

import pytest

from lib.hashing import append_hash


def _make_hashed_shares(count, start_x=1):
    """Build (raw_share, hashed_share) pairs with real hashing."""
    pairs = []
    for i in range(count):
        raw = f"{start_x + i}-abcdef{i:04x}"
        pairs.append((raw, append_hash(raw)))
    return pairs


def _build_channel_data(hashed_shares, separator="|"):
    return separator.join(hashed_shares)


class TestReceiverChannelWorker:

    def test_sets_ready_event_before_calling_target(self):
        from receiver import _receiver_channel_worker

        call_order = []

        class TrackingEvent:
            def set(self):
                call_order.append("ready")

        def fake_target():
            call_order.append("target")
            return "data"

        evt = TrackingEvent()
        q = multiprocessing.Queue()
        _receiver_channel_worker(evt, fake_target, (), q, "ARP")
        assert call_order == ["ready", "target"]

    def test_puts_ok_result_on_success(self):
        from receiver import _receiver_channel_worker

        evt = MagicMock()
        q = multiprocessing.Queue()
        _receiver_channel_worker(evt, lambda: "test_data", (), q, "ARP")
        status, channel, data = q.get(timeout=2)
        assert status == "ok"
        assert channel == "ARP"
        assert data == "test_data"

    def test_puts_error_on_exception(self):
        from receiver import _receiver_channel_worker

        def failing_target():
            raise RuntimeError("connection refused")

        evt = MagicMock()
        q = multiprocessing.Queue()
        _receiver_channel_worker(evt, failing_target, (), q, "MTNS")
        status, channel, msg = q.get(timeout=2)
        assert status == "error"
        assert channel == "MTNS"
        assert "connection refused" in msg

    def test_passes_args_to_target(self):
        from receiver import _receiver_channel_worker

        received_args = []

        def capture_target(a, b, c):
            received_args.extend([a, b, c])
            return "ok"

        evt = MagicMock()
        q = multiprocessing.Queue()
        _receiver_channel_worker(evt, capture_target, (1, 2, 3), q, "TEST")
        assert received_args == [1, 2, 3]


class TestSendAck:

    @patch("receiver.send")
    @patch("receiver.Raw")
    @patch("receiver.TCP")
    @patch("receiver.IP")
    def test_send_ack_crafts_correct_packet(self, mock_ip, mock_tcp, mock_raw, mock_send):
        from receiver import _send_ack

        mock_ip.return_value = MagicMock()
        mock_tcp.return_value = MagicMock()
        mock_raw.return_value = MagicMock()
        mock_ip.return_value.__truediv__ = MagicMock(return_value=MagicMock())
        mock_ip.return_value.__truediv__.return_value.__truediv__ = MagicMock(
            return_value=MagicMock()
        )

        _send_ack("192.168.100.3", "192.168.100.6", 9999, "enp0s9")

        mock_ip.assert_called_once_with(src="192.168.100.6", dst="192.168.100.3")
        mock_tcp.assert_called_once()
        tcp_kwargs = mock_tcp.call_args
        assert tcp_kwargs[1].get("flags") == "A" or (
            len(tcp_kwargs[0]) >= 1 and "A" in str(tcp_kwargs)
        )
        mock_raw.assert_called_once_with(load=b"ACK")
        mock_send.assert_called_once()


class TestShareValidation:

    def test_valid_shares_identified(self):
        from receiver import _validate_shares

        arp_pairs = _make_hashed_shares(2, start_x=1)
        mtns_pairs = _make_hashed_shares(5, start_x=3)

        tagged = [("ARP", h) for _, h in arp_pairs] + [("MTNS", h) for _, h in mtns_pairs]
        valid, invalid = _validate_shares(tagged)
        assert len(valid) == 7
        assert len(invalid) == 0

    def test_invalid_share_discarded(self):
        from receiver import _validate_shares

        arp_pairs = _make_hashed_shares(2, start_x=1)
        mtns_pairs = _make_hashed_shares(5, start_x=3)

        corrupted = mtns_pairs[0][1][:-1] + ("0" if mtns_pairs[0][1][-1] != "0" else "1")
        tagged = [("ARP", h) for _, h in arp_pairs]
        tagged.append(("MTNS", corrupted))
        tagged.extend([("MTNS", h) for _, h in mtns_pairs[1:]])
        valid, invalid = _validate_shares(tagged)
        assert len(valid) == 6
        assert len(invalid) == 1
        assert invalid[0][0] == "MTNS"

    def test_provenance_tags_preserved(self):
        from receiver import _validate_shares

        arp_pairs = _make_hashed_shares(2, start_x=1)
        mtns_pairs = _make_hashed_shares(3, start_x=3)
        tagged = [("ARP", h) for _, h in arp_pairs] + [("MTNS", h) for _, h in mtns_pairs]
        valid, _ = _validate_shares(tagged)
        arp_count = sum(1 for ch, _ in valid if ch == "ARP")
        mtns_count = sum(1 for ch, _ in valid if ch == "MTNS")
        assert arp_count == 2
        assert mtns_count == 3


class TestReconstructionSuccess:

    @patch("receiver.reconstruct_secret", return_value="Attack at dawn")
    def test_reconstruct_called_with_valid_shares(self, mock_reconstruct):
        from receiver import _attempt_reconstruction
        from lib.config import PRIME, THRESHOLD_K

        valid_shares = [("ARP", f"{i}-abc{i:04x}") for i in range(1, 7)]
        result = _attempt_reconstruction(valid_shares, [], {}, THRESHOLD_K, PRIME)
        assert result == "Attack at dawn"
        mock_reconstruct.assert_called_once()
        args = mock_reconstruct.call_args[0]
        assert len(args[0]) == 6
        assert args[1] == PRIME

    @patch("receiver.reconstruct_secret", return_value="Attack at dawn")
    def test_reconstruct_not_called_with_too_few_shares(self, mock_reconstruct):
        from receiver import _attempt_reconstruction
        from lib.config import PRIME, THRESHOLD_K

        valid_shares = [("ARP", f"{i}-abc{i:04x}") for i in range(1, 4)]
        result = _attempt_reconstruction(valid_shares, [], {}, THRESHOLD_K, PRIME)
        assert result is None
        mock_reconstruct.assert_not_called()


class TestDiagnostics:

    @patch("receiver.reconstruct_secret")
    def test_failure_diagnostics_logged(self, mock_reconstruct, capsys):
        from receiver import _attempt_reconstruction
        from lib.config import PRIME, THRESHOLD_K

        valid_shares = [("ARP", "1-abc"), ("MTNS", "3-def")]
        invalid = [("MTNS", "4-corrupt")]
        results = {"ARP": ("ok", "data"), "MTNS": ("ok", "data")}
        _attempt_reconstruction(valid_shares, invalid, results, THRESHOLD_K, PRIME)

        captured = capsys.readouterr().out
        assert "[RECEIVER] FAILED" in captured or "Not enough valid shares" in captured
        assert "Diagnostics" in captured
        mock_reconstruct.assert_not_called()


class TestDegradedMode:

    @patch("receiver.reconstruct_secret", return_value="Secret msg")
    def test_arp_failure_mtns_success(self, mock_reconstruct):
        from receiver import _attempt_reconstruction
        from lib.config import PRIME, THRESHOLD_K

        # ARP failed; 5 MTNS shares still satisfy k=4
        valid_shares = [("MTNS", f"{i}-data{i:04x}") for i in range(1, 6)]
        results = {"ARP": ("error", "timeout"), "MTNS": ("ok", "data")}
        result = _attempt_reconstruction(valid_shares, [], results, THRESHOLD_K, PRIME)
        assert result == "Secret msg"
        mock_reconstruct.assert_called_once()


class TestLogging:

    @patch("receiver._send_ack")
    @patch("receiver.reconstruct_secret", return_value="Hello world")
    def test_receiver_prefix_in_output(self, mock_reconstruct, mock_ack, capsys):
        from receiver import _attempt_reconstruction
        from lib.config import PRIME, THRESHOLD_K

        valid_shares = [("ARP", f"{i}-abc{i:04x}") for i in range(1, 6)]
        _attempt_reconstruction(
            valid_shares, [], {"ARP": ("ok", "d"), "MTNS": ("ok", "d")},
            THRESHOLD_K, PRIME
        )
        captured = capsys.readouterr().out
        assert "[RECEIVER]" in captured
        assert "Reconstructing" in captured or "Secret message" in captured

    def test_validation_logging(self, capsys):
        from receiver import _validate_shares

        pairs = _make_hashed_shares(2, start_x=1)
        tagged = [("ARP", h) for _, h in pairs]
        _validate_shares(tagged)
        captured = capsys.readouterr().out
        assert captured.count("[RECEIVER]") >= 2
        assert "VALID" in captured

    def test_provenance_breakdown_logged(self, capsys):
        from receiver import _validate_shares

        arp_pairs = _make_hashed_shares(2, start_x=1)
        mtns_pairs = _make_hashed_shares(3, start_x=3)
        tagged = [("ARP", h) for _, h in arp_pairs] + [("MTNS", h) for _, h in mtns_pairs]
        _validate_shares(tagged)
        captured = capsys.readouterr().out
        assert "from ARP" in captured
        assert "from MTNS" in captured


class TestChannelTimeout:

    def test_timeout_produces_error_not_crash(self):
        from receiver import _receiver_channel_worker
        import queue as queue_module

        def timeout_target():
            raise TimeoutError("channel timed out")

        evt = MagicMock()
        q = multiprocessing.Queue()
        _receiver_channel_worker(evt, timeout_target, (), q, "ARP")
        status, channel, msg = q.get(timeout=2)
        assert status == "error"
        assert channel == "ARP"
        assert "timed out" in msg
