"""utils.stream_command watchdog timeout testleri."""

import sys
import time
import unittest

from skopos import utils


class StreamCommandTimeoutTest(unittest.TestCase):
    def test_silent_hang_is_killed_by_watchdog(self):
        # Hiç çıktı üretmeden 10s uyuyan süreç — eski satır-arası kontrol
        # bunu asla yakalayamazdı. Watchdog ~1s'de öldürmeli.
        start = time.monotonic()
        rc, out = utils.stream_command(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=1,
        )
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 5, "watchdog süreci zamanında öldürmedi")
        self.assertNotEqual(rc, 0)

    def test_fast_command_completes_normally_with_timeout_set(self):
        rc, out = utils.stream_command(
            [sys.executable, "-c", "print('hello skopos')"],
            timeout=30,
        )
        self.assertEqual(rc, 0)
        self.assertIn("hello skopos", out)

    def test_missing_binary_returns_127(self):
        rc, out = utils.stream_command(["skopos-no-such-binary-xyz"])
        self.assertEqual(rc, 127)


if __name__ == "__main__":
    unittest.main()
