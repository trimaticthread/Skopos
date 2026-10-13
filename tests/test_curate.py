"""curate.py karakterizasyon testleri: mevcut davranışı kilitler."""

import json
import os
import tempfile
import unittest

from skopos import curate


def _write(run_dir, name, content):
    with open(os.path.join(run_dir, name), "w", encoding="utf-8") as fh:
        fh.write(content)


class CurateFfufTest(unittest.TestCase):
    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix="skopos_test_")

    def _ffuf(self, results):
        _write(self.run_dir, "ffuf0.json", json.dumps({"results": results}))

    def test_dominant_group_eliminated_as_noise(self):
        noise = [{"url": f"http://t/x{i}", "input": {"FUZZ": f"x{i}"},
                  "status": 200, "length": 100} for i in range(20)]
        signal = [
            {"url": "http://t/admin", "input": {"FUZZ": "admin"},
             "status": 200, "length": 5000},
            {"url": "http://t/backup", "input": {"FUZZ": "backup"},
             "status": 301, "length": 0},
        ]
        self._ffuf(noise + signal)
        hits, note = curate._curate_ffuf(self.run_dir)
        self.assertIsNone(note)
        urls = {h["url"] for h in hits}
        self.assertIn("http://t/admin", urls)
        self.assertIn("http://t/backup", urls)
        self.assertNotIn("http://t/x0", urls)

    def test_all_same_response_yields_note_and_no_hits(self):
        same = [{"url": f"http://t/x{i}", "input": {"FUZZ": f"x{i}"},
                 "status": 301, "length": 0} for i in range(20)]
        self._ffuf(same)
        hits, note = curate._curate_ffuf(self.run_dir)
        self.assertEqual(hits, [])
        self.assertIsNotNone(note)
        self.assertIn("vhost", note.lower())

    def test_small_result_set_kept_as_is(self):
        few = [{"url": "http://t/a", "input": {"FUZZ": "a"},
                "status": 200, "length": 10},
               {"url": "http://t/b", "input": {"FUZZ": "b"},
                "status": 200, "length": 20}]
        self._ffuf(few)
        hits, note = curate._curate_ffuf(self.run_dir)
        self.assertIsNone(note)
        self.assertEqual(len(hits), 2)


class ClassifyFfufTest(unittest.TestCase):
    def test_dirs_files_apis_split(self):
        hits = [
            {"url": "http://t/admin", "input": "admin", "status": 200, "length": 1},
            {"url": "http://t/config.php", "input": "config.php",
             "status": 200, "length": 1},
            {"url": "http://t/api/users", "input": "users", "status": 200, "length": 1},
        ]
        dirs, files, apis = curate._classify_ffuf(hits)
        self.assertEqual([d["url"] for d in dirs], ["http://t/admin"])
        self.assertEqual([f["url"] for f in files], ["http://t/config.php"])
        self.assertEqual([a["url"] for a in apis], ["http://t/api/users"])


class CurateNiktoTest(unittest.TestCase):
    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix="skopos_test_")

    def test_noise_dropped_important_first(self):
        log = (
            "- Nikto v2.5.0\n"
            "+ Server: nginx/1.18.0\n"
            "+ Suggested security header missing: X-Frame-Options\n"
            "+ /admin/: Possible admin login page found.\n"
            "+ OSVDB-3233: /icons/README: Apache default file found.\n"
        )
        _write(self.run_dir, "web_nikto0.log", log)
        res = curate._curate_nikto(self.run_dir)
        self.assertNotIn("Suggested security header missing: X-Frame-Options", res)
        self.assertTrue(any("/admin/" in x for x in res))
        self.assertTrue(any("OSVDB-3233" in x for x in res))
        # önemli olanlar listenin başında
        self.assertTrue("/admin/" in res[0] or "OSVDB" in res[0])

    def test_spa_detection(self):
        _write(self.run_dir, "web_whatweb0.log", "http://t [200] React, webpack")
        self.assertTrue(curate._detect_spa(self.run_dir))

    def test_no_spa(self):
        _write(self.run_dir, "web_whatweb0.log", "http://t [200] nginx, PHP")
        self.assertFalse(curate._detect_spa(self.run_dir))


if __name__ == "__main__":
    unittest.main()
