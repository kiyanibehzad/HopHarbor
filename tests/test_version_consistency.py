"""Keep source-build version metadata aligned across available platform shells."""
import ast
from pathlib import Path
import plistlib
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def constants(path):
    values = {}
    for node in ast.parse(path.read_text(encoding='utf-8')).body:
        if not isinstance(node, ast.Assign):
            continue
        if isinstance(node.value, ast.Constant):
            value = node.value.value
        elif isinstance(node.value, ast.Name) and node.value.id in values:
            value = values[node.value.id]
        else:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                values[target.id] = value
    return values


class VersionConsistencyTests(unittest.TestCase):
    def test_controller_and_platform_metadata_agree(self):
        backend = constants(ROOT / 'manager.py')
        expected = backend['VERSION'], str(backend['BUILD'])
        self.assertEqual((backend['MAC_VERSION'], str(backend['MAC_BUILD'])), expected)
        linux = constants(ROOT / 'linux_desktop.py')
        self.assertEqual((linux['VERSION'], str(linux['BUILD'])), expected)
        with (ROOT / 'packaging/Info.plist').open('rb') as source:
            mac = plistlib.load(source)
        self.assertEqual((mac['CFBundleShortVersionString'], mac['CFBundleVersion']), expected)
        windows = constants(ROOT / 'packaging/build_windows.py')
        self.assertEqual((windows['VERSION'], str(windows['BUILD'])), expected)
        for project in (ROOT / 'packaging/windows').glob('*/*.csproj'):
            with self.subTest(project=project.name):
                metadata = ET.parse(project).getroot()
                self.assertEqual(metadata.findtext('.//Version'), expected[0])
                self.assertEqual(metadata.findtext('.//FileVersion'), '.'.join(expected))
        web = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        self.assertIn("appInfo.version||'" + expected[0] + "'", web)
        self.assertIn('appInfo.build??' + expected[1], web)
        html = (ROOT / 'web/index.html').read_text(encoding='utf-8')
        self.assertIn('>v' + expected[0] + ' &middot; build ' + expected[1] + '</span>', html)


    def test_windows_default_project_and_installer_metadata_agree(self):
        backend = constants(ROOT / 'manager.py')
        version, build = backend['VERSION'], str(backend['BUILD'])
        for project in (ROOT / 'packaging/windows').glob('*/*.csproj'):
            with self.subTest(project=project.name):
                metadata = ET.parse(project).getroot()
                self.assertEqual(metadata.findtext('.//AssemblyVersion'), version + '.' + build)
                informational = metadata.findtext('.//InformationalVersion')
                if informational is not None:
                    self.assertEqual(informational, version)
                if project.parent.name == 'Desktop':
                    entries = metadata.findall(".//AssemblyMetadata[@Include='HopHarborBuild']")
                    self.assertEqual(len(entries), 1)
                    self.assertEqual(entries[0].get('Value'), build)
        installer = (ROOT / 'packaging/windows/HopHarbor.iss').read_text(encoding='utf-8')
        for key, expected in (('AppVersion', version), ('AppBuild', build)):
            defaults = re.findall(r'^\s*#define\s+' + key + r'\s+"([^"\n]+)"\s*$',
                                  installer, flags=re.MULTILINE)
            self.assertEqual(defaults, [expected], key)


if __name__ == '__main__':
    unittest.main()
