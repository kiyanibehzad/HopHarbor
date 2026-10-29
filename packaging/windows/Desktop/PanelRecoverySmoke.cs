#if PANEL_AUTH_TESTS
// Opt-in compiled fixture. Excluded entirely from shipped app assemblies.
using System.Net.Http;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace HopHarbor.Desktop;

internal sealed partial class PanelForm
{
    private int rendererFailures;
    private async Task<JsonElement> FixtureAsync(string command)
    {
        Control control = await ReadControlAsync();
        using var client = new HttpClient(new HttpClientHandler { UseProxy = false });
        client.DefaultRequestHeaders.Add("X-HopHarbor-Test", control.token);
        using var response = await client.PostAsync("http://127.0.0.1:" + control.port + "/__fixture/" + command, new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        response.EnsureSuccessStatusCode();
        using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return result.RootElement.Clone();
    }

    private async Task WaitUntilAsync(Func<bool> predicate, string failure, int iterations = 200)
    {
        for (int i = 0; i < iterations; i++) { if (predicate()) return; await Task.Delay(100); }
        throw new InvalidOperationException(failure);
    }

    private async Task TriggerAndWaitRecoveryAsync(Action trigger)
    {
        long generation = viewGeneration;
        int ready = acceptedReadyMessages;
        trigger();
        await WaitUntilAsync(() => viewGeneration != generation && acceptedReadyMessages > ready, "Panel did not complete native recovery.");
        await WaitForPanelAsync();
    }

    private async Task RunPanelAuthSmokeAsync()
    {
        var checks = new List<string>();
        string? failure = null;
        try
        {
            await WaitForPanelAsync();
            await WaitUntilAsync(() => acceptedReadyMessages > 0, "Native ready event missing.");
            ControlStamp? originalStamp = ReadControlStamp();
            int originalPort = activePort;
            Require((await EvaluateAsync("location.hash")).GetString() == "", "Bootstrap fragment retained.");
            checks.Add("Actual production Manager/Handler + WebView2 bootstrap clears fragment and accepts ready");

            int priorReady = acceptedReadyMessages;
            int priorRecoveries = automaticRecoveries;
            // Try direct, parent-native and parent-adapter calls from a real
            // child, including a synchronous about:blank child script.
            string frameCode = "try{window.chrome.webview.postMessage({action:'ready'})}catch{};try{parent.chrome.webview.postMessage({action:'reauthenticate',reason:'retry'})}catch{};try{parent.postNativePanelMessage({action:'ready'})}catch{};parent.document.documentElement.dataset.fixtureFrameDone='yes';";
            await EvaluateAsync("(()=>{const f=document.createElement('iframe');document.body.appendChild(f);const s=f.contentDocument.createElement('script');s.textContent=" + JsonSerializer.Serialize(frameCode) + ";f.contentDocument.head.appendChild(s);return true})()");
            Require((await EvaluateAsync("document.documentElement.dataset.fixtureFrameDone")).GetString() == "yes", "Synchronous about:blank child script did not execute.");
            await Task.Delay(500);
            Require(bridgeRevoked && pendingRecovery is null && priorReady == acceptedReadyMessages && priorRecoveries == automaticRecoveries, "About:blank child/parent bridge bypassed revocation.");
            ReleaseView(); await OpenPanelAsync(); await WaitForPanelAsync();
            priorReady = acceptedReadyMessages;
            await EvaluateAsync("(()=>{const f=document.createElement('iframe');f.srcdoc=" + JsonSerializer.Serialize("<script>" + frameCode + "</script>") + ";document.body.appendChild(f);return true})()");
            await Task.Delay(500);
            Require(bridgeRevoked && pendingRecovery is null && priorReady == acceptedReadyMessages, "Srcdoc child bypassed revocation.");
            ReleaseView(); await OpenPanelAsync(); await WaitForPanelAsync();
            priorReady = acceptedReadyMessages;
            await EvaluateAsync("(()=>{const f=document.createElement('iframe');f.src='/__fixture/frame';document.body.appendChild(f);return true})()");
            await Task.Delay(500);
            Require(bridgeRevoked && pendingRecovery is null && priorReady == acceptedReadyMessages, "URL child bypassed revocation.");
            ReleaseView(); await OpenPanelAsync(); await WaitForPanelAsync();
            priorReady = acceptedReadyMessages;
            foreach (string bad in new[] {"null", "[]", "{}", "{\"action\":\"ready\",\"port\":1}", "{\"action\":\"reauthenticate\",\"reason\":\"retry\",\"token\":\"bad\"}"})
                await EvaluateAsync("window.chrome.webview.postMessage(" + bad + ")");
            HandlePanelMessage(browser!, viewGeneration, "http://evil.invalid/", "{\"action\":\"ready\"}");
            HandlePanelMessage(browser!, viewGeneration, "http://127.0.0.1:" + activePort + "/other", "{\"action\":\"reauthenticate\",\"reason\":\"retry\"}");
            HandlePanelMessage(browser!, viewGeneration - 1, "http://127.0.0.1:" + activePort + "/", "{\"action\":\"ready\"}");
            Require(priorReady == acceptedReadyMessages && pendingRecovery is null, "Malformed/foreign/path/stale message accepted.");
            var core = browser!.CoreWebView2;
            await EvaluateAsync("location.href='/index.html'");
            await Task.Delay(300);
            Require(ReferenceEquals(core, browser.CoreWebView2) && browser.CoreWebView2.Source.EndsWith('/'), "Second document navigation was accepted in the same view.");
            checks.Add("Real about:blank/srcdoc/URL iframe parent-native and parent-adapter attacks revoked; malformed/foreign/path/stale guards pass");

            await FixtureAsync("state403");
            await EvaluateAsync("(refresh(true),true)");
            await Task.Delay(2400);
            Require(priorRecoveries == automaticRecoveries && !(await EvaluateAsync("document.getElementById('lockedScreen').hidden")).GetBoolean(), "403 auto-recovered or did not lock.");
            await FixtureAsync("normal");
            await TriggerAndWaitRecoveryAsync(() => _ = EvaluateAsync("document.getElementById('lockedRetry').click()"));
            checks.Add("403 locks without automatic recovery; actual Retry button reauthenticates");

            core = browser!.CoreWebView2;
            var cookies = await core.CookieManager.GetCookiesAsync("http://127.0.0.1:" + activePort + "/");
            var cookie = cookies.Single(c => c.Name == "pm_session");
            cookie.Expires = DateTime.UtcNow.AddSeconds(1);
            core.CookieManager.AddOrUpdateCookie(cookie);
            await Task.Delay(1800);
            Require(!(await core.CookieManager.GetCookiesAsync("http://127.0.0.1:" + activePort + "/")).Any(c => c.Name == "pm_session"), "Synthetic browser cookie did not expire.");
            await TriggerAndWaitRecoveryAsync(() => _ = EvaluateAsync("(refresh(true),true)"));
            Require(originalStamp == ReadControlStamp() && activePort == originalPort, "Cookie recovery changed control.");
            checks.Add("Real WebView2 cookie expiration recovers with unchanged control/port/backend");

            await FixtureAsync("expire-session");
            await TriggerAndWaitRecoveryAsync(() => _ = EvaluateAsync("(refresh(true),true)"));
            Require(originalStamp == ReadControlStamp(), "Server invalidation changed control.");
            checks.Add("Real server-side session invalidation recovers with unchanged control/backend");

            await TriggerAndWaitRecoveryAsync(() => _ = EvaluateAsync("(request('/api/__fixture-mutation',{method:'POST',body:{synthetic:true}}).catch(()=>{}),true)"));
            var stats = await FixtureAsync("stats");
            Require(stats.GetProperty("mutations").GetInt32() == 1, "Failed mutation was replayed.");
            checks.Add("401 failed POST is observed once and never replayed after recovery");

            priorRecoveries = automaticRecoveries;
            await FixtureAsync("state401");
            await EvaluateAsync("(refresh(true),true)");
            await Task.Delay(3200);
            Require(automaticRecoveries == priorRecoveries && pendingRecovery is null, "Three-per-minute budget exceeded.");
            await FixtureAsync("normal");
            await TriggerAndWaitRecoveryAsync(() => _ = EvaluateAsync("document.getElementById('lockedRetry').click()"));
            checks.Add("Three automatic recoveries exhaust rolling budget; manual Retry remains usable");

            await FixtureAsync("bootstrap401");
            long before = viewGeneration;
            await EvaluateAsync("document.getElementById('lockedRetry').click()");
            await WaitUntilAsync(() => viewGeneration != before && !opening && documentActive, "Manual bootstrap did not load.");
            await Task.Delay(3000);
            priorRecoveries = automaticRecoveries;
            await Task.Delay(2300);
            Require(priorRecoveries == automaticRecoveries && pendingRecovery is null, "Failed bootstrap entered a loop.");
            await FixtureAsync("normal");
            await TriggerAndWaitRecoveryAsync(() => _ = EvaluateAsync("document.getElementById('lockedRetry').click()"));
            checks.Add("Rejected bootstrap stays locked without recursive automatic retry; Retry recovers after correction");

            var staleView = browser!; long staleGeneration = viewGeneration;
            string source = staleView.CoreWebView2.Source;
            ScheduleRecovery(staleView, staleGeneration, manual: true);
            var pending = pendingRecovery;
            Require(pending is not null, "Expected one scheduled recovery.");
            ScheduleRecovery(staleView, staleGeneration, manual: true);
            Require(ReferenceEquals(pending, pendingRecovery), "Duplicate pending recovery created.");
            HandlePanelMessage(staleView, staleGeneration - 1, source, "{\"action\":\"ready\"}");
            Require(ReferenceEquals(pending, pendingRecovery), "Stale ready canceled current work.");
            HandlePanelMessage(staleView, staleGeneration, source, "{\"action\":\"ready\"}");
            Require(pendingRecovery is null, "Valid ready failed to cancel pending work.");
            checks.Add("One pending recovery; stale ready rejected and valid ready cancels queued work");

            ScheduleRecovery(staleView, staleGeneration, manual: true);
            HidePanel();
            Require(browser is null && pendingRecovery is null && !Visible, "Hide left a pending view.");
            priorReady = acceptedReadyMessages;
            HandlePanelMessage(staleView, staleGeneration, source, "{\"action\":\"ready\"}");
            Require(priorReady == acceptedReadyMessages, "Disposed view accepted ready.");
            await OpenPanelAsync(); await WaitForPanelAsync();
            checks.Add("Hide cancels queued recovery; stale disposed view rejected; reopen reauthenticates");

            HidePanel();
            Task openingView = OpenPanelAsync();
            HidePanel();
            Task reopeningView = OpenPanelAsync();
            await Task.WhenAll(openingView, reopeningView);
            await WaitForPanelAsync();
            Require(Visible && browser is not null && !opening, "Rapid hide/reopen lost the requested view.");
            checks.Add("Hide during asynchronous opening followed by immediate reopen completes a fresh view");

            // Crash only this disposable fixture's renderer using its own CDP
            // endpoint, then observe the actual production ProcessFailed event.
            priorRecoveries = automaticRecoveries;
            int failures = rendererFailures;
            try { await browser!.CoreWebView2.CallDevToolsProtocolMethodAsync("Page.crash", "{}").WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (Exception) { }
            await WaitUntilAsync(() => rendererFailures > failures, "Actual renderer failure event missing.");
            await Task.Delay(2200);
            Require(automaticRecoveries == priorRecoveries, "Renderer path bypassed automatic budget.");
            await TriggerAndWaitRecoveryAsync(() => ScheduleRecovery(browser!, viewGeneration, manual: true));
            checks.Add("Actual WebView2 renderer crash reports ProcessFailed, honors exhausted budget and supports explicit recovery");

            stats = await FixtureAsync("stats");
            Require(stats.GetProperty("mutations").GetInt32() == 1 && originalStamp == ReadControlStamp() && activePort == originalPort, "Fixture controller state drifted.");
            var stored = await EvaluateAsync("({hash:location.hash,storage:Object.keys(localStorage).filter(k=>k!=='hopharbor.appearance'&&k!=='hopharbor.dismissedSetupNote'),session:Object.keys(sessionStorage)})");
            Require(stored.GetProperty("hash").GetString() == "" && stored.GetProperty("storage").GetArrayLength() == 0 && stored.GetProperty("session").GetArrayLength() == 0, "Unexpected browser storage.");
            checks.Add("Control file stays unchanged; no token fragment/storage and one mutation throughout");
        }
        catch (Exception error) { failure = error is InvalidOperationException ? error.Message : error.GetType().Name; }
        File.WriteAllText(Path.Combine(data, "panel-auth-smoke-results.json"), JsonSerializer.Serialize(new { ok = failure is null, checks, error = failure, automaticRecoveries }, new JsonSerializerOptions { WriteIndented = true }));
        allowClose = true; Close();
    }
}
#endif
