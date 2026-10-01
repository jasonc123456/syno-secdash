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
        css = open(os.path.join(UI, "dashboard.css")).read()
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
        """DSM 7.2+ native window: config keyed by the loader JS file."""
        cfg = json.load(open(os.path.join(UI, "config")))
        self.assertEqual(list(cfg), ["SecDash.js"])
        mods = cfg["SecDash.js"]
        app = mods["SYNO.SDS.SecDash.Application"]
        self.assertEqual(app["type"], "app")
        self.assertEqual(app["appWindow"], "SYNO.SDS.SecDash.MainWindow")
        self.assertFalse(app["allUsers"])
        self.assertEqual(mods["SYNO.SDS.SecDash.MainWindow"]["type"], "lib")
        info = open(os.path.join(ROOT, "INFO.in")).read()
        self.assertIn('dsmappname="SYNO.SDS.SecDash.Application"', info)
        self.assertIn('dsmuidir="ui"', info)
        for n in (16, 24, 32, 48, 64, 72, 256):
            self.assertTrue(os.path.exists(os.path.join(UI, "images", "secdash_%d.png" % n)))

    def test_dsm_loader_is_namespaced(self):
        """SecDash.js runs inside DSM's desktop: it may only define our classes."""
        js = open(os.path.join(UI, "SecDash.js")).read()
        names = re.findall(r'Ext\.(?:define|namespace)\("([^"]+)"', js)
        self.assertTrue(names)
        for n in names:
            self.assertTrue(n.startswith("SYNO.SDS.SecDash."), n)
        cfg = json.load(open(os.path.join(UI, "config")))
        for mod in cfg["SecDash.js"]:
            self.assertIn(mod, js)
        self.assertIn("webman/3rdparty/SecDash/index.html", js)
        self.assertNotIn("document.write", js)

if __name__ == "__main__":
    unittest.main()
