using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Win32;
using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace HopHarbor.Desktop;

internal static class Program
{
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);

    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        SetCurrentProcessExplicitAppUserModelID("io.github.kiyanibehzad.HopHarbor");
        try
        {
            Architecture architecture = RuntimeInformation.OSArchitecture;
            int minimumBuild = architecture == Architecture.Arm64 ? 22000 : 19045;
            if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, minimumBuild)
                || architecture is not (Architecture.X64 or Architecture.Arm64))
                throw new InvalidOperationException("HopHarbor requires Windows 10 22H2 or later on x64, or Windows 11 or later on ARM64.");
            if (RuntimeInformation.ProcessArchitecture != architecture)
                throw new InvalidOperationException("Open the HopHarbor package matching this computer's native x64 or ARM64 architecture.");
            string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HopHarbor");
            bool background = false;
            bool smoke = false;
            bool quitPanel = false;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--data-dir" && i + 1 < args.Length) data = args[++i];
                else if (args[i] == "--background") background = true;
                else if (args[i] == "--smoke-test") smoke = true;
                else if (args[i] == "--quit-panel") quitPanel = true;
                else throw new InvalidOperationException("Unrecognized HopHarbor launch option.");
            }
            if (!Path.IsPathFullyQualified(data)) throw new InvalidOperationException("The data directory must be an absolute path.");
            data = Path.GetFullPath(data);
            if (smoke && (background || !Path.GetFileName(data).StartsWith("HopHarbor-Smoke-", StringComparison.OrdinalIgnoreCase)
                || !data.StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath())) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("UI smoke tests require a separate HopHarbor-Smoke-* directory inside this user's temporary directory.");
            string sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new InvalidOperationException("Cannot identify this Windows user.");
            string identity = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid + "\n" + data.ToUpperInvariant())))[..24];
            using var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, "Local\\HopHarbor.Show." + identity);
            using var quitEvent = new EventWaitHandle(false, EventResetMode.AutoReset, "Local\\HopHarbor.Quit." + identity);
            using var instance = new Mutex(true, "Local\\HopHarbor.Panel." + identity, out bool first);
            if (quitPanel) { if (!first) quitEvent.Set(); return 0; }
            if (!first) { showEvent.Set(); return 0; }
            using var form = new PanelForm(data, showEvent, quitEvent, background, smoke);
            Application.Run(form);
            return 0;
        }
        catch (Exception error)
        {
            MessageBox.Show(error is InvalidOperationException ? error.Message : "HopHarbor could not open its local panel. Check the installation and private data directory.",
                "HopHarbor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}

internal sealed class PanelForm : Form
{
    private const string Repository = "https://github.com/kiyanibehzad/HopHarbor";
    private readonly string app;
    private readonly string data;
    private readonly EventWaitHandle showEvent;
    private readonly EventWaitHandle quitEvent;
    private readonly bool startBackground;
    private readonly bool smokeTest;
    private readonly NotifyIcon tray;
    private readonly System.Windows.Forms.Timer eventTimer;
    private WebView2? browser;
    private bool allowClose;
    private bool opening;
    private bool packagePrepared;
    private int activePort;
    private long viewGeneration;
    private ControlStamp? observedControlStamp;
    private long nextControlCheck;
    private long nextControlRecovery;
    private int automaticRecoveries;
    private int privateToolInvocations;
    private Icon? trayIcon;
    private readonly Label message;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);
    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);

    public PanelForm(string dataDirectory, EventWaitHandle show, EventWaitHandle quit, bool background, bool smoke)
    {
        app = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, ".."));
        data = dataDirectory;
        showEvent = show;
        quitEvent = quit;
        startBackground = background;
        smokeTest = smoke;
        Text = "HopHarbor";
        Width = 1120; Height = 760;
        MinimumSize = new Size(780, 560);
        StartPosition = FormStartPosition.CenterScreen;
        Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? SystemIcons.Application;
        message = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Text = "Starting your local connection service…", Padding = new Padding(32) };
        Controls.Add(message);
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open HopHarbor", null, async (_, _) => await OpenPanelAsync());
        menu.Items.Add("Reload Panel", null, async (_, _) => { ReleaseView(); await OpenPanelAsync(); });
        menu.Items.Add("Keep in System Tray", null, (_, _) => HidePanel());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Closing the panel keeps connections running") { Enabled = false });
        menu.Items.Add("Quit Panel", null, (_, _) => { allowClose = true; Close(); });
        tray = new NotifyIcon { Text = "HopHarbor — connections run independently of this panel", ContextMenuStrip = menu, Visible = true };
        tray.DoubleClick += async (_, _) => await OpenPanelAsync();
        eventTimer = new System.Windows.Forms.Timer { Interval = 250 };
        eventTimer.Tick += async (_, _) =>
        {
            if (quitEvent.WaitOne(0)) { allowClose = true; Close(); return; }
            if (showEvent.WaitOne(0)) await OpenPanelAsync();
            await CheckControllerChangeAsync();
        };
        eventTimer.Start();
        SystemEvents.UserPreferenceChanged += ThemeChanged;
        FormClosing += (_, e) => { if (!allowClose && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; HidePanel(); } };
        Shown += async (_, _) =>
        {
            ApplyChromeTheme();
            if (startBackground)
            {
                HidePanel();
                try { await EnsureBackendAsync(); }
                catch (Exception error)
                {
                    ShowInTaskbar = true; Show(); Activate();
                    message.Text = error is InvalidOperationException ? error.Message : "The local service could not start. Check OpenSSH Client and the installation.";
                    message.Show();
                }
            }
            else
            {
                await OpenPanelAsync();
                if (smokeTest) await RunSmokeAsync();
            }
        };
    }

    private static bool SystemDark()
    {
        if (SystemInformation.HighContrast) return SystemColors.Window.GetBrightness() < .5;
        try { using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"); return Convert.ToInt32(key?.GetValue("AppsUseLightTheme", 1)) == 0; }
        catch { return false; }
    }

    private void ApplyChromeTheme()
    {
        bool dark = SystemDark();
        BackColor = dark ? Color.FromArgb(17, 17, 19) : Color.White;
        message.BackColor = BackColor; message.ForeColor = dark ? Color.Gainsboro : Color.FromArgb(35, 35, 38);
        int enabled = dark ? 1 : 0;
        if (IsHandleCreated && OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
            _ = DwmSetWindowAttribute(Handle, 20, ref enabled, sizeof(int));
        Icon next = CreateTrayIcon(dark);
        tray.Icon = next;
        trayIcon?.Dispose(); trayIcon = next;
    }

    private static Icon CreateTrayIcon(bool dark)
    {
        using var bitmap = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Color color = SystemInformation.HighContrast ? SystemColors.WindowText : dark ? Color.White : Color.FromArgb(25, 25, 27);
            using var pen = new Pen(color, 4.1f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            using var brush = new SolidBrush(color);
            g.DrawLine(pen, 6, 6, 6, 26); g.DrawLine(pen, 26, 6, 26, 26);
            g.DrawBezier(pen, 6, 15, 12, 22, 20, 22, 26, 15);
            foreach (int x in new[] { 6, 26 }) foreach (int y in new[] { 6, 26 }) g.FillEllipse(brush, x - 2.8f, y - 2.8f, 5.6f, 5.6f);
        }
        IntPtr handle = bitmap.GetHicon();
        try { using var temporary = Icon.FromHandle(handle); return (Icon)temporary.Clone(); }
        finally { DestroyIcon(handle); }
    }

    private async void ThemeChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (IsDisposed || !IsHandleCreated) return;
        try
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => ThemeChanged(sender, e))); return; }
            ApplyChromeTheme();
            if (browser?.CoreWebView2 != null)
                await browser.CoreWebView2.ExecuteScriptAsync("window.HopHarborSystemDark=" + (SystemDark() ? "true" : "false") + ";window.dispatchEvent(new Event('hopharbor-system-appearance'));");
        }
        catch (InvalidOperationException) { }
    }

    private async Task<string> RunPrivateToolAsync(string executable, IEnumerable<string> arguments, int timeoutSeconds = 15)
    {
        privateToolInvocations++;
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = app };
        foreach (string value in arguments) start.ArgumentList.Add(value);
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start a HopHarbor component.");
        child.StandardInput.Close();
        Task<string> output = child.StandardOutput.ReadToEndAsync();
        Task<string> errors = child.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try { await child.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { try { child.Kill(entireProcessTree: true); } catch { } throw new InvalidOperationException("The local HopHarbor component did not respond in time."); }
        string text = await output;
        _ = await errors;
        if (child.ExitCode != 0) throw new InvalidOperationException("HopHarbor could not verify or start this private installation. Open the matching installation and check its local service.");
        if (text.Length > 32768) throw new InvalidOperationException("Invalid local component response.");
        return text;
    }

    private async Task EnsureBackendAsync()
    {
        if (!packagePrepared)
        {
            await RunPrivateToolAsync(Path.Combine(app, "bin", "HopHarborHelper.exe"), new[] { "prepare-package", "--app-dir", app });
            packagePrepared = true;
        }
        await RunPrivateToolAsync(Path.Combine(app, "bin", "HopHarborHelper.exe"), new[] { "prepare", "--data-dir", data });
        await RunPrivateToolAsync(Path.Combine(app, "runtime", "pythonw.exe"), new[] { Path.Combine(app, "install_windows.py"), "--launch", "--app-dir", app, "--data-dir", data }, 30);
    }

    private sealed record Control(bool ok, int port, string token);
    private readonly record struct ControlStamp(long WriteTicks, long CreationTicks, long Length);

    private ControlStamp? ReadControlStamp()
    {
        // Metadata is only an untrusted change hint. ReadControlAsync still
        // requires the native helper's private ACL/reparse validation before
        // any token is read or any WebView navigation is performed.
        try
        {
            var file = new FileInfo(Path.Combine(data, "control.json"));
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0) return null;
            return new(file.LastWriteTimeUtc.Ticks, file.CreationTimeUtc.Ticks, file.Length);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private async Task CheckControllerChangeAsync()
    {
        long now = Environment.TickCount64;
        if (IsDisposed || !Visible || WindowState == FormWindowState.Minimized || opening
            || observedControlStamp is null || now < nextControlCheck) return;
        nextControlCheck = now + 2000;
        ControlStamp? current = ReadControlStamp();
        if (current is null || current == observedControlStamp || now < nextControlRecovery) return;
        // A stopped service alone does not trigger a launch. Only a replacement
        // control file does, so intentional installer stops remain stopped.
        nextControlRecovery = now + 5000;
        long generation = viewGeneration;
        string? appearance = null;
        try
        {
            if (browser?.CoreWebView2 is not null)
            {
                string value = await browser.CoreWebView2.ExecuteScriptAsync("document.documentElement.dataset.appearance").WaitAsync(TimeSpan.FromSeconds(1));
                string? candidate = JsonSerializer.Deserialize<string>(value);
                if (candidate is "system" or "light" or "dark") appearance = candidate;
            }
        }
        catch (Exception) { }
        // Closing/hiding while the public appearance value is read cancels the
        // recovery. Reopening will authenticate through the normal path.
        if (IsDisposed || !Visible || WindowState == FormWindowState.Minimized || opening || generation != viewGeneration) return;
        automaticRecoveries++;
        ReleaseView();
        await OpenPanelAsync(appearance, activate: false);
        if (browser is null) nextControlRecovery = Environment.TickCount64 + 10000;
    }

    private async Task<Control> ReadControlAsync()
    {
        string text = await RunPrivateToolAsync(Path.Combine(app, "bin", "HopHarborHelper.exe"), new[] { "control", "--data-dir", data });
        var control = JsonSerializer.Deserialize<Control>(text) ?? throw new InvalidOperationException("Invalid panel connection settings.");
        if (!control.ok || control.port < 1024 || control.port > 65535 || control.token is null || Encoding.UTF8.GetByteCount(control.token) < 16 || Encoding.UTF8.GetByteCount(control.token) > 4096)
            throw new InvalidOperationException("Invalid panel connection settings.");
        return control;
    }

    private bool Allowed(Uri? uri) => uri is not null && uri.Scheme == "http" && uri.Host == "127.0.0.1" && uri.Port == activePort && string.IsNullOrEmpty(uri.UserInfo);

    private static bool IsRepository(string? value) => Uri.TryCreate(value, UriKind.Absolute, out var u) && u.Scheme == "https" && u.Host == "github.com" && u.Port == 443 && string.IsNullOrEmpty(u.UserInfo) && u.AbsolutePath.TrimEnd('/') == "/kiyanibehzad/HopHarbor" && string.IsNullOrEmpty(u.Query);

    private async Task OpenPanelAsync(string? restoredAppearance = null, bool activate = true)
    {
        if (opening || IsDisposed) return;
        if (activate) { ShowInTaskbar = true; Show(); if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal; Activate(); }
        if (browser != null) { if (activate) browser.Focus(); return; }
        opening = true;
        long generation = ++viewGeneration;
        message.Text = "Starting your local connection service…"; message.Show();
        WebView2? view = null;
        try
        {
            await EnsureBackendAsync();
            ControlStamp? stamp = ReadControlStamp();
            Control control = await ReadControlAsync();
            if (generation != viewGeneration || IsDisposed) return;
            activePort = control.port;
            view = new WebView2 { Dock = DockStyle.Fill, DefaultBackgroundColor = BackColor };
            browser = view; Controls.Add(view); view.BringToFront();
            var env = await CoreWebView2Environment.CreateAsync(null, Path.Combine(data, "browser"), new CoreWebView2EnvironmentOptions("--no-proxy-server"));
            await view.EnsureCoreWebView2Async(env);
            if (generation != viewGeneration || IsDisposed) return;
            var core = view.CoreWebView2;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.AreHostObjectsAllowed = false;
            core.Settings.IsWebMessageEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;
            core.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;
            core.DownloadStarting += (_, e) => e.Cancel = true;
            core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            core.WebResourceRequested += (_, e) =>
            {
                if (!Allowed(Uri.TryCreate(e.Request.Uri, UriKind.Absolute, out var uri) ? uri : null))
                    e.Response = env.CreateWebResourceResponse(null, 403, "External resources are disabled", "Content-Type: text/plain");
            };
            core.FrameNavigationStarting += (_, e) => { if (!Allowed(Uri.TryCreate(e.Uri, UriKind.Absolute, out var uri) ? uri : null)) e.Cancel = true; };
            core.NavigationStarting += (_, e) =>
            {
                if (!Allowed(Uri.TryCreate(e.Uri, UriKind.Absolute, out var uri) ? uri : null))
                {
                    e.Cancel = true;
                    if (e.IsUserInitiated && IsRepository(e.Uri)) OpenRepository();
                }
            };
            core.NewWindowRequested += (_, e) =>
            {
                e.Handled = true;
                if (e.IsUserInitiated && IsRepository(e.Uri)) OpenRepository();
            };
            core.ProcessFailed += (_, _) => { if (!IsDisposed && generation == viewGeneration) { ReleaseView(); message.Text = "The local panel stopped responding. Use Reload Panel in the system tray. Your connections continue in the background."; message.Show(); } };
            string version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.3.0";
            string build = Assembly.GetExecutingAssembly().GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(x => x.Key == "HopHarborBuild")?.Value ?? "10";
            string metadata = JsonSerializer.Serialize(new { version, build });
            await core.AddScriptToExecuteOnDocumentCreatedAsync("window.HopHarborNativeVersion=" + metadata + ";window.HopHarborPlatform='win32';window.HopHarborSystemDark=" + (SystemDark() ? "true" : "false") + ";");
            if (restoredAppearance is "system" or "light" or "dark")
            {
                string preference = JsonSerializer.Serialize(restoredAppearance);
                await core.AddScriptToExecuteOnDocumentCreatedAsync("try{const a=" + preference + ";if(a==='system')localStorage.removeItem('hopharbor.appearance');else localStorage.setItem('hopharbor.appearance',a);}catch{}");
            }
            // Record the pre-validation stamp: a replacement during the helper
            // call must remain detectable on the next bounded metadata check.
            observedControlStamp = stamp ?? default(ControlStamp);
            core.Navigate("http://127.0.0.1:" + control.port + "/#token=" + Uri.EscapeDataString(control.token));
            message.Hide(); if (activate) view.Focus();
        }
        catch (WebView2RuntimeNotFoundException)
        {
            ReleaseView(); message.Text = "Install the Microsoft Edge WebView2 Runtime from Microsoft, then open HopHarbor again. Your background connections continue independently."; message.Show();
        }
        catch (Exception error)
        {
            if (generation == viewGeneration && !IsDisposed) { ReleaseView(); message.Text = error is InvalidOperationException ? error.Message : "The local panel could not open. Check the installation and try Reload Panel."; message.Show(); }
        }
        finally { opening = false; }
    }

    private void ReleaseView()
    {
        viewGeneration++;
        var old = browser; browser = null;
        if (old != null) { Controls.Remove(old); old.Dispose(); }
        activePort = 0;
    }

    private void HidePanel() { ReleaseView(); ShowInTaskbar = false; Hide(); }

    private static void OpenRepository()
    {
        try { Process.Start(new ProcessStartInfo(Repository) { UseShellExecute = true }); }
        catch (System.ComponentModel.Win32Exception) { }
    }

    private async Task<JsonElement> EvaluateAsync(string expression)
    {
        if (browser?.CoreWebView2 is null) throw new InvalidOperationException("The synthetic panel is not ready.");
        string result = await browser.CoreWebView2.ExecuteScriptAsync(expression);
        using var parsed = JsonDocument.Parse(result);
        return parsed.RootElement.Clone();
    }

    private async Task WaitForPanelAsync()
    {
        for (int i = 0; i < 120; i++)
        {
            try { if ((await EvaluateAsync("document.getElementById('serviceLabel')?.textContent==='Local service online'")).GetBoolean()) return; }
            catch (Exception) { }
            await Task.Delay(100);
        }
        throw new InvalidOperationException("The synthetic panel did not authenticate.");
    }

    private static void Require(bool value, string failure)
    {
        if (!value) throw new InvalidOperationException(failure);
    }

    private async Task CheckAutomaticRestartRecoveryAsync()
    {
        if (browser?.CoreWebView2 is null) throw new InvalidOperationException("Synthetic browser disappeared before restart.");
        var previousCore = browser.CoreWebView2;
        int previousPort = activePort;
        int previousRecoveries = automaticRecoveries;
        await RunPrivateToolAsync(Path.Combine(app, "runtime", "pythonw.exe"),
            new[] { Path.Combine(app, "install_windows.py"), "--stop", "--app-dir", app, "--data-dir", data }, 30);
        // The smoke flag already requires a fresh, empty, isolated data scope.
        // Holding its released old port makes the new-port regression repeatable
        // without terminating any process or changing networking settings.
        var oldPort = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, previousPort);
        oldPort.ExclusiveAddressUse = true;
        try
        {
            oldPort.Start();
            await RunPrivateToolAsync(Path.Combine(app, "runtime", "pythonw.exe"),
                new[] { Path.Combine(app, "install_windows.py"), "--launch", "--app-dir", app, "--data-dir", data }, 30);
            Control replacement = await ReadControlAsync();
            Require(replacement.port != previousPort, "Synthetic restart did not choose a new loopback port.");
            bool recovered = false;
            for (int i = 0; i < 120; i++)
            {
                if (automaticRecoveries > previousRecoveries && activePort == replacement.port
                    && browser?.CoreWebView2 is not null && !ReferenceEquals(browser.CoreWebView2, previousCore))
                {
                    await WaitForPanelAsync();
                    Require((await EvaluateAsync("location.hash")).GetString() == ""
                        && (await EvaluateAsync("document.documentElement.dataset.theme")).GetString() == "dark",
                        "Recovered panel did not clear bootstrap access or preserve appearance.");
                    recovered = true;
                    break;
                }
                await Task.Delay(100);
            }
            Require(recovered, "Visible panel did not automatically recover after the controller selected a new port.");
        }
        finally { oldPort.Stop(); }
    }

    private async Task RunSmokeAsync()
    {
        var checks = new List<string>();
        string? failure = null;
        try
        {
            await WaitForPanelAsync();
            var overview = await EvaluateAsync("({title:document.getElementById('pageTitle').textContent,platform:window.HopHarborPlatform,version:document.getElementById('appVersion').textContent,fragment:location.hash,servers:document.getElementById('metricServers').textContent,tunnels:document.getElementById('metricTunnels').textContent})");
            Require(overview.GetProperty("servers").GetString() == "0" && overview.GetProperty("tunnels").GetString() == "0", "UI smoke test refuses a non-empty configuration.");
            Require(overview.GetProperty("title").GetString() == "Overview" && overview.GetProperty("platform").GetString() == "win32"
                && overview.GetProperty("version").GetString()!.Contains("1.3.0") && overview.GetProperty("version").GetString()!.Contains("build 10")
                && overview.GetProperty("fragment").GetString() == "", "Overview, version or cleared bootstrap fragment failed.");
            checks.Add("Authenticated empty Overview, Windows platform, version and cleared bootstrap fragment");
            int idleTools = privateToolInvocations;
            await Task.Delay(2300);
            Require(privateToolInvocations == idleTools, "Idle metadata monitoring is spawning native tools.");
            checks.Add("Idle controller change monitoring does not spawn native helpers");
            await EvaluateAsync("(goView('servers'),document.getElementById('primaryAction').click(),true)");
            var editor = await EvaluateAsync("({open:document.getElementById('serverDialog').open,auth:Array.from(document.getElementById('serverAuth').options).map(o=>o.value),keepalive:document.getElementById('serverKeepaliveInterval').value,text:document.getElementById('serverDialog').textContent})");
            Require(editor.GetProperty("open").GetBoolean() && editor.GetProperty("auth").GetArrayLength() == 4
                && editor.GetProperty("keepalive").GetString() == "30" && editor.GetProperty("text").GetString()!.Contains("Windows"), "Windows Session editor failed.");
            checks.Add("Session editor, all authentication choices, Windows credential label and keepalive");
            await EvaluateAsync("(document.getElementById('serverDialog').close(),goView('dashboard'),changeAppearance('light'),window.HopHarborSystemDark=true,window.dispatchEvent(new Event('hopharbor-system-appearance')),true)");
            Require((await EvaluateAsync("document.documentElement.dataset.theme")).GetString() == "light", "Explicit Light did not override System.");
            await EvaluateAsync("(changeAppearance('system'),true)");
            Require((await EvaluateAsync("document.documentElement.dataset.theme")).GetString() == "dark", "System Dark did not apply.");
            await EvaluateAsync("(window.HopHarborSystemDark=false,window.dispatchEvent(new Event('hopharbor-system-appearance')),true)");
            Require((await EvaluateAsync("document.documentElement.dataset.theme")).GetString() == "light", "System Light did not apply.");
            await EvaluateAsync("(changeAppearance('dark'),true)");
            Require((await EvaluateAsync("document.documentElement.dataset.theme")).GetString() == "dark", "Explicit Dark failed.");
            checks.Add("System Light/Dark events and explicit appearance overrides");
            if (browser?.CoreWebView2 is null) throw new InvalidOperationException("Synthetic browser disappeared.");
            using (var png = File.Create(Path.Combine(data, "ui-smoke.png")))
                await browser.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, png);
            HidePanel();
            Require(browser is null && !Visible && !ShowInTaskbar && tray.Visible, "Hidden panel did not release its WebView or retain the tray.");
            checks.Add("Close/hide releases WebView and leaves the tray icon");
            await OpenPanelAsync(); await WaitForPanelAsync();
            Require((await EvaluateAsync("document.documentElement.dataset.theme")).GetString() == "dark"
                && (await EvaluateAsync("location.hash")).GetString() == "", "Reopen did not reauthenticate and preserve appearance.");
            checks.Add("Reopen reauthenticates and preserves the appearance choice");
            browser!.CoreWebView2.Navigate("https://example.com/");
            await Task.Delay(300);
            Require(Allowed(browser.Source), "External navigation was not blocked.");
            checks.Add("External navigation rejected without a privileged JS bridge");
            await CheckAutomaticRestartRecoveryAsync();
            checks.Add("Visible panel automatically reauthenticates after backend restart/new port and preserves appearance");
            await EnsureBackendAsync();
            checks.Add("Independent backend remains healthy before panel exit");
        }
        catch (Exception error) { failure = error is InvalidOperationException ? error.Message : error.GetType().Name; }
        File.WriteAllText(Path.Combine(data, "ui-smoke-results.json"), JsonSerializer.Serialize(new { ok = failure is null, checks, error = failure }, new JsonSerializerOptions { WriteIndented = true }));
        allowClose = true; Close();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            SystemEvents.UserPreferenceChanged -= ThemeChanged;
            eventTimer.Stop(); eventTimer.Dispose(); ReleaseView();
            tray.Visible = false; tray.Dispose(); trayIcon?.Dispose();
        }
        base.Dispose(disposing);
    }
}
