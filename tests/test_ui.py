import json
import os
import re
import unittest

from tests.helpers import ROOT

UI = os.path.join(ROOT, "package", "ui")


class UiPackagingTest(unittest.TestCase):
    def test_css_is_scoped(self):
        """DSM can load a third-party app's stylesheet into its own desktop page,
        so every rule must be scoped to html.sd or it restyles DSM itself."""
        css = open(os.path.join(UI, "secdash.css")).read()
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        bad = []
        for head in re.findall(r"(?:^|[{}])\s*([^{}@]+?)\s*\{", css):
            for sel in head.split(","):
                sel = sel.strip()
                if sel and not sel.startswith("html.sd"):
                    bad.append(sel)
        self.assertEqual(bad, [])

    def test_no_generic_asset_names(self):
        for name in ("style.css", "app.js", "script.js"):
            self.assertFalse(os.path.exists(os.path.join(UI, name)), name)

    def test_index_references_exist(self):
        html = open(os.path.join(UI, "index.html")).read()
        self.assertIn('class="sd"', html)
        for ref in re.findall(r'(?:href|src)="([^"#:]+)"', html):
            self.assertTrue(os.path.exists(os.path.join(UI, ref)), ref)

    def test_dsm_app_config(self):
        cfg = json.load(open(os.path.join(UI, "config")))
        app = cfg[".url"]["SYNO.SDS._ThirdParty.App.SecDash"]
        self.assertEqual(app["type"], "legacy")  # iframe inside a DSM window
        self.assertNotIn("appWindow", app)       # only for native JS apps
        self.assertFalse(app["allUsers"])
        self.assertTrue(app["url"].startswith("/webman/3rdparty/SecDash/"))
        info = open(os.path.join(ROOT, "INFO.in")).read()
        self.assertIn('dsmappname="SYNO.SDS._ThirdParty.App.SecDash"', info)
        for n in (16, 24, 32, 48, 64, 72, 256):
            self.assertTrue(os.path.exists(os.path.join(UI, "images", "secdash_%d.png" % n)))


if __name__ == "__main__":
    unittest.main()
