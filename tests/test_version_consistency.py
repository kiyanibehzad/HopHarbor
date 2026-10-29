"""Keep source-build version metadata aligned across available platform shells."""
import ast
from pathlib import Path
import plistlib
import unittest


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
        html = (ROOT / 'web/index.html').read_text(encoding='utf-8')
        self.assertIn('>v' + expected[0] + ' &middot; build ' + expected[1] + '</span>', html)


if __name__ == '__main__':
    unittest.main()
