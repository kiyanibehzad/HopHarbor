"""Compile and execute the production recovery policy without Windows/UI."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class WindowsPanelRecovery(unittest.TestCase):
    def test_compiled_policy(self):
        dotnet = os.environ.get('HOPHARBOR_TEST_DOTNET') or shutil.which('dotnet')
        if not dotnet:
            self.skipTest('Set HOPHARBOR_TEST_DOTNET to run compiled Windows recovery policy')
        with tempfile.TemporaryDirectory(prefix='hopharbor-policy-') as temp:
            stage = Path(temp)
            shutil.copyfile(ROOT / 'packaging/windows/Desktop/PanelRecovery.cs', stage / 'PanelRecovery.cs')
            shutil.copyfile(ROOT / 'packaging/windows/Desktop/PanelFilePolicy.cs', stage / 'PanelFilePolicy.cs')
            (stage / 'Policy.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup></Project>')
            (stage / 'Program.cs').write_text(r'''using HopHarbor.Desktop;
int count = 0;
void Check(bool value) { count++; if (!value) throw new Exception("Policy assertion " + count); }
var p = new PanelRecoveryPolicy();
Check(p.Delay(false, 10000) == 0);
Check(p.Delay(false, 10001) == 1999);
Check(p.Delay(false, 12001) == 1999);
Check(p.Delay(false, 14000) is null);
Check(p.Delay(true, 14000) == 2000);
Check(p.Delay(false, 69999) is null);
Check(p.Delay(false, 70000) == 0);
foreach (string path in new[]{"/", "/index.html"}) Check(PanelRecoveryPolicy.Trusted("http://127.0.0.1:32123"+path,32123));
foreach (string url in new[]{"https://127.0.0.1:32123/", "http://localhost:32123/", "http://127.0.0.1:32124/", "http://evil:32123/", "http://user@127.0.0.1:32123/", "http://127.0.0.1:32123/other", "http://127.0.0.1:32123/a/../", "http://127.0.0.1:32123/%69ndex.html", "http://127.0.0.1:32123/?url=x", "http://127.0.0.1:32123/#token=x", "http://127.1:32123/", "file:///index.html"}) Check(!PanelRecoveryPolicy.Trusted(url,32123));
Check(!PanelRecoveryPolicy.Trusted(null,32123));
Check(PanelRecoveryPolicy.Command("{\"action\":\"ready\"}") == "ready");
Check(PanelRecoveryPolicy.Command("{\"action\":\"reauthenticate\",\"reason\":\"retry\"}") == "retry");
Check(PanelRecoveryPolicy.Command("{\"action\":\"reauthenticate\",\"reason\":\"authentication\"}") == "authentication");
foreach (string bad in new[]{"null", "[]", "1", "{", "{}", "{\"action\":true}", "{\"action\":\"ready\",\"reason\":\"retry\"}", "{\"action\":\"ready\",\"action\":\"ready\"}", "{\"action\":\"reauthenticate\"}", "{\"action\":\"reauthenticate\",\"reason\":\"url\"}", "{\"action\":\"ready\",\"token\":\"secret\"}", new string(' ', 257)}) Check(PanelRecoveryPolicy.Command(bad) is null);

foreach (string url in new[]{"https://github.com/kiyanibehzad/HopHarbor", "https://github.com/kiyanibehzad/HopHarbor/releases", "https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2"}) Check(PanelFilePolicy.OfficialLink(url));
foreach (string url in new[]{"http://github.com/kiyanibehzad/HopHarbor", "https://github.com.evil/kiyanibehzad/HopHarbor", "https://user@github.com/kiyanibehzad/HopHarbor", "https://github.com/kiyanibehzad/HopHarbor/releases?url=x", "https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2#x", "https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2\n", "https://github.com/kiyanibehzad/HopHarbor/releases/../evil", "file:///tmp/x", "https://github.com/kiyanibehzad/HopHarbor/releases/tag/v1.4.2-preview"}) Check(!PanelFilePolicy.OfficialLink(url));
string valid = "{\"action\":\"exportConfiguration\",\"document\":{\"format\":\"HopHarbor configuration\",\"schema_version\":1}}";
Check(PanelFilePolicy.ExportDocument(valid) is not null);
foreach (string bad in new[]{"null", "[]", "{", "{}", valid.Replace("configuration", "wrong"), valid.Replace("\"document\":", "\"path\":\"C:\\\\x\",\"document\":"), valid.Replace("\"document\":", "\"action\":\"exportConfiguration\",\"document\":"), "{\"action\":\"exportConfiguration\",\"document\":true}", valid.Replace("\"schema_version\":1", "\"x\":\"" + new string('é', 140000) + "\"")}) Check(PanelFilePolicy.ExportDocument(bad) is null);
Console.WriteLine("Policy assertions passed: " + count);
''')
            env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
            result = subprocess.run([dotnet, 'run', '--project', str(stage/'Policy.csproj'), '--configuration', 'Release'], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('Policy assertions passed: 59', result.stdout)
