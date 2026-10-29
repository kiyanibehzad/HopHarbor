using Microsoft.Web.WebView2.WinForms;
using System.Text.Json;

namespace HopHarbor.Desktop;

internal sealed partial class PanelForm
{
    private readonly PanelRecoveryPolicy recoveryPolicy = new();
    private CancellationTokenSource? pendingRecovery;
    private CancellationTokenSource? loadDeadline;
    private bool documentActive;
    private bool bridgeRevoked;
    private bool needsRecovery;
    private int acceptedReadyMessages;

    private bool CurrentDocument(WebView2 view, long generation, string? source)
        => !IsDisposed && ReferenceEquals(browser, view) && generation == viewGeneration
            && documentActive && !bridgeRevoked && PanelRecoveryPolicy.Trusted(source, activePort)
            && PanelRecoveryPolicy.Trusted(view.CoreWebView2?.Source, activePort);

    private void HandlePanelMessage(WebView2 view, long generation, string source, string json)
    {
        if (!CurrentDocument(view, generation, source)) return;
        switch (PanelRecoveryPolicy.Command(json))
        {
            case "ready":
                acceptedReadyMessages++;
                CancelRecovery();
                needsRecovery = false;
                // Success does not erase rolling attempt history: intermittent
                // success cannot bypass the three-per-minute ceiling.
                break;
            case "authentication": ScheduleRecovery(view, generation, manual: false); break;
            case "retry": ScheduleRecovery(view, generation, manual: true); break;
        }
    }

    private void CancelRecovery()
    {
        var pending = pendingRecovery;
        pendingRecovery = null;
        pending?.Cancel();
    }

    private void CancelLoadDeadline()
    {
        var pending = loadDeadline;
        loadDeadline = null;
        pending?.Cancel();
    }

    private async void StartLoadDeadline(WebView2 view, long generation)
    {
        CancelLoadDeadline();
        using var pending = new CancellationTokenSource();
        loadDeadline = pending;
        try
        {
            await Task.Delay(20000, pending.Token);
            if (ReferenceEquals(loadDeadline, pending))
            {
                loadDeadline = null;
                ScheduleRecovery(view, generation, manual: false);
            }
        }
        catch (OperationCanceledException) { }
    }

    private void ScheduleRecovery(WebView2 view, long generation, bool manual)
    {
        if (IsDisposed || !ReferenceEquals(browser, view) || generation != viewGeneration) return;
        needsRecovery = true;
        if (!Visible || WindowState == FormWindowState.Minimized || pendingRecovery is not null) return;
        int? delay = recoveryPolicy.Delay(manual, Environment.TickCount64);
        if (delay is null) return;
        var pending = new CancellationTokenSource();
        pendingRecovery = pending;
        _ = RecoverPanelAsync(view, generation, delay.Value, pending);
    }

    private async Task RecoverPanelAsync(WebView2 view, long generation, int delay, CancellationTokenSource pending)
    {
        try
        {
            // Always yield out of WebView2 event callbacks before disposing a view.
            await Task.Delay(Math.Max(1, delay), pending.Token);
            while (opening) await Task.Delay(100, pending.Token);
            if (opening || pending.IsCancellationRequested || !ReferenceEquals(pendingRecovery, pending)
                || IsDisposed || !Visible || WindowState == FormWindowState.Minimized
                || !ReferenceEquals(browser, view) || generation != viewGeneration) return;
            string? appearance = null;
            try
            {
                if (PanelRecoveryPolicy.Trusted(view.CoreWebView2.Source, activePort))
                {
                    string value = await view.CoreWebView2.ExecuteScriptAsync("document.documentElement.dataset.appearance").WaitAsync(TimeSpan.FromSeconds(1), pending.Token);
                    string? candidate = JsonSerializer.Deserialize<string>(value);
                    if (candidate is "system" or "light" or "dark") appearance = candidate;
                }
            }
            catch (Exception) { }
            if (pending.IsCancellationRequested || !ReferenceEquals(pendingRecovery, pending)
                || IsDisposed || !Visible || WindowState == FormWindowState.Minimized
                || !ReferenceEquals(browser, view) || generation != viewGeneration) return;
            pendingRecovery = null;
            automaticRecoveries++;
            ReleaseView();
            // Only read/validate existing private control. Do not launch, stop,
            // restart, or change any controller/SSH/forwarding process here.
            await OpenPanelAsync(appearance, activate: false, startBackend: false);
        }
        catch (OperationCanceledException) { }
        catch (Exception)
        {
            if (!IsDisposed && generation == viewGeneration)
            {
                message.Text = "The local panel could not recover. Use Reload Panel in the system tray. Your connections remain independent.";
                message.Show();
            }
        }
        finally
        {
            if (ReferenceEquals(pendingRecovery, pending)) pendingRecovery = null;
            pending.Dispose();
        }
    }
}
