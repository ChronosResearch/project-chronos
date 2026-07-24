# mypy: ignore-errors
"""Integration tests for the ChronosAgent orchestrator.

All real subsystems (FHE, PoSW, drand) are replaced with precise mocks so
these tests run in milliseconds with no network I/O or CPU-bound computation.

Tests verify:
    - Correct deadline calculation from drand round data.
    - The full async state machine executes all five phases in sequence.
    - The pre-erasure commitment is generated and verified correctly.
    - Memory wipe is called exactly once.
    - The correct round number is awaited from the drand oracle.
    - The SNARK prover stub is invoked during Phase 4e.
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Suppress the anti-tamper engine in all tests — it would fire on pytest's trace hook.
os.environ["CHRONOS_DISABLE_ANTI_TAMPER"] = "true"

from chronos_agent import ChronosAgent  # noqa: E402


def _make_agent(duration_sec: int = 3) -> ChronosAgent:
    """Build a ChronosAgent with fully mocked subsystem dependencies."""
    mock_fhe = MagicMock()
    mock_posw = MagicMock()
    mock_drand = AsyncMock()

    # FHE mock — provides a zeroisable key buffer
    mock_fhe.get_private_key_bytes.return_value = bytearray(
        b"MOCK_SECRET_KEY_32BYTES_PADDING!"
    )
    mock_fhe.encrypt_data.return_value = (111, 222)
    mock_fhe.evaluate_inference.return_value = 333

    # drand mock — reports current round as 1000
    mock_drand.fetch_latest_round.return_value = {"round": 1000, "signature": "a" * 96}
    mock_drand.wait_for_round.return_value = {"round": 1001, "signature": "a" * 96}

    # PoSW mock — compute_posw is synchronous void, derive_encryption_key returns bytes
    mock_posw.compute_posw.return_value = None
    mock_posw.derive_encryption_key.return_value = b"\x00" * 32

    # SNARK prover stub — NoopSNARKProver returns 192 zero bytes
    from interfaces import NoopSNARKProver

    mock_snark = NoopSNARKProver()

    return ChronosAgent(
        fhe_engine=mock_fhe,
        posw_manager=mock_posw,
        drand=mock_drand,
        mission_duration_sec=duration_sec,
        snark_prover=mock_snark,
    )


class TestChronosAgentDeadline(unittest.IsolatedAsyncioTestCase):

    async def test_deadline_calculation(self) -> None:
        """Target round = current_round + ceil(duration / interval)."""
        agent = _make_agent(duration_sec=3)
        await agent._initialise_target_deadline()
        # duration=3s, interval=3s → 1 additional round → 1000 + 1 = 1001
        self.assertEqual(agent.target_round, 1001)

    async def test_deadline_rounds_up_short_duration(self) -> None:
        """Even a 1-second duration must wait at least 1 round (max(1, ...))."""
        agent = _make_agent(duration_sec=1)
        await agent._initialise_target_deadline()
        self.assertGreaterEqual(agent.target_round, 1001)


class TestChronosAgentInitValidation(unittest.TestCase):

    def test_rejects_non_positive_mission_duration(self) -> None:
        mock_fhe = MagicMock()
        mock_posw = MagicMock()
        mock_drand = AsyncMock()
        mock_fhe.get_private_key_bytes.return_value = bytearray(b"k" * 32)

        with self.assertRaises(ValueError):
            ChronosAgent(mock_fhe, mock_posw, mock_drand, mission_duration_sec=0)
        with self.assertRaises(ValueError):
            ChronosAgent(mock_fhe, mock_posw, mock_drand, mission_duration_sec=-3)

    def test_rejects_snark_prover_without_prove(self) -> None:
        mock_fhe = MagicMock()
        mock_posw = MagicMock()
        mock_drand = AsyncMock()
        mock_fhe.get_private_key_bytes.return_value = bytearray(b"k" * 32)

        with self.assertRaises(TypeError):
            ChronosAgent(
                mock_fhe,
                mock_posw,
                mock_drand,
                mission_duration_sec=3,
                snark_prover=object(),
            )


class TestChronosAgentMission(unittest.IsolatedAsyncioTestCase):

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_full_mission_state_machine(self, mock_wipe: MagicMock) -> None:
        """The five-phase state machine must execute all steps in sequence."""

        # We need zeroize_buffer to actually zero the buffer or the proof will fail.
        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        agent = _make_agent(duration_sec=3)
        await agent.run_mission()

        # Phase 2 — FHE inference ran
        agent.fhe_engine.encrypt_data.assert_called_once()
        agent.fhe_engine.evaluate_inference.assert_called_once_with((111, 222))

        # Phase 3 — Waited for the correct drand round
        agent.drand.wait_for_round.assert_called_once_with(1001)

        # Phase 4a — PoSW key derived
        agent.posw_manager.derive_encryption_key.assert_called_once()

        # Phase 4c — Memory wipe executed exactly once
        mock_wipe.assert_called_once_with(agent.raw_sk_buffer)

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_buffer_is_zeroed_after_mission(self, mock_wipe: MagicMock) -> None:
        """raw_sk_buffer must be all zeros after the mission completes."""

        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        agent = _make_agent(duration_sec=3)
        await agent.run_mission()

        self.assertTrue(
            all(b == 0 for b in agent.raw_sk_buffer),
            "SK buffer still contains non-zero bytes after mission completion.",
        )

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_wipe_called_exactly_once(self, mock_wipe: MagicMock) -> None:
        """The memory wipe must be called exactly once, not zero or multiple times."""

        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        agent = _make_agent(duration_sec=3)
        await agent.run_mission()

        self.assertEqual(
            mock_wipe.call_count,
            1,
            f"zeroize_buffer was called {mock_wipe.call_count} times; expected exactly 1.",
        )

    async def test_initialise_deadline_raises_on_empty_round(self) -> None:
        """_initialise_target_deadline must raise CryptographicSanityError if drand returns no data."""
        agent = _make_agent()
        agent.drand.fetch_latest_round.return_value = None
        from exceptions import CryptographicSanityError

        with self.assertRaises(CryptographicSanityError):
            await agent._initialise_target_deadline()

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_anti_tamper_stopped_in_mission(self, mock_wipe: MagicMock) -> None:
        """The anti-tamper engine must be stopped if it was initialized."""

        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        mock_anti = MagicMock()
        agent = _make_agent(duration_sec=3)
        agent._anti_tamper = mock_anti

        await agent.run_mission()
        mock_anti.stop.assert_called_once()

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_sanity_failed_on_chunk_larger_than_q(self, mock_wipe: MagicMock) -> None:
        """Should raise CryptographicSanityError if a chunk is >= q."""
        agent = _make_agent()
        from exceptions import CryptographicSanityError

        with patch("chronos_agent.ZERO_KNOWLEDGE_Q", 2):
            with self.assertRaises(CryptographicSanityError):
                await agent.run_mission()

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_sanity_failed_on_invalid_schnorr_proof(self, mock_wipe: MagicMock) -> None:
        """Should raise CryptographicSanityError if Schnorr proof fails verification."""

        def _do_wipe(buf: bytearray) -> None:
            for i in range(len(buf)):
                buf[i] = 0

        mock_wipe.side_effect = _do_wipe

        agent = _make_agent()
        import builtins

        from exceptions import CryptographicSanityError

        real_pow = builtins.pow
        call_count = 0

        def mock_pow(base, exp, mod=None):
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                return 9999
            return real_pow(base, exp, mod)

        with patch("chronos_agent.pow", side_effect=mock_pow):
            with self.assertRaises(CryptographicSanityError):
                await agent.run_mission()

    @patch("chronos_agent.MemorySanitizer.zeroize_buffer")
    async def test_memory_integrity_failed_on_non_zero_buffer(
        self, mock_wipe: MagicMock
    ) -> None:
        """Should raise MemoryIntegrityError if key buffer is not fully zeroed."""
        agent = _make_agent()
        from exceptions import MemoryIntegrityError

        with self.assertRaises(MemoryIntegrityError):
            await agent.run_mission()

    @patch("sys.argv", ["chronos_agent.py", "--duration", "1"])
    @patch("chronos_agent.ChronosAgentFactory.create")
    async def test_async_main(self, mock_factory: MagicMock) -> None:
        mock_agent = AsyncMock()
        mock_factory.return_value = mock_agent

        from chronos_agent import _async_main

        await _async_main()

        mock_factory.assert_called_once_with(1)
        mock_agent.run_mission.assert_called_once()


if __name__ == "__main__":
    unittest.main()
