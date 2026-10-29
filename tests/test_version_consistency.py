"""Keep shipped platform shells and controller metadata on one version/build."""
import ast
from pathlib import Path
import plistlib
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]

def constants(path):
    result = {}
    for node in ast.parse(path.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = node.value.value
    return result

class VersionConsistencyTests(unittest.TestCase):
    def test_controller_and_platform_metadata_agree(self):
        backend = constants(ROOT / 'manager.py')
        version, build = backend['VERSION'], str(backend['BUILD'])
        linux = constants(ROOT / 'linux_desktop.py')
        self.assertEqual((linux['VERSION'], str(linux['BUILD'])), (version, build))
        windows = constants(ROOT / 'packaging/build_windows.py')
        self.assertEqual((windows['VERSION'], str(windows['BUILD'])), (version, build))
        with (ROOT / 'packaging/Info.plist').open('rb') as source:
            mac = plistlib.load(source)
        self.assertEqual((mac['CFBundleShortVersionString'],mac['CFBundleVersion']), (version, build))
        web=(ROOT / 'web/app.js').read_text(encoding='utf-8')
        self.assertIn("appInfo.version||'"+version+"'", web)
        self.assertIn('appInfo.build??'+build, web)
        html = (ROOT / 'web/index.html').read_text(encoding='utf-8')
        self.assertIn('>v'+version+' &middot; build '+build+'</span>', html)
        projects = list((ROOT / 'packaging/windows').glob('*/*.csproj'))
        for project in projects:
            with self.subTest(project=project.name):
                metadata=ET.parse(project).getroot()
                self.assertEqual(metadata.findtext('.//Version'), version)
                self.assertEqual(metadata.findtext('.//FileVersion'), version+'.'+build)

if __name__ == '__main__':
    unittest.main()
