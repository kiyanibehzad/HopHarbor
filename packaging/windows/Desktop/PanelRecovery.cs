using System.Text.Json;

namespace HopHarbor.Desktop;

// Independent of WinForms: the same policy is compiled by the host regression.
internal sealed class PanelRecoveryPolicy
{
    private readonly Queue<long> attempts = new();
    private long? lastScheduled;
    internal int? Delay(bool manual, long now)
    {
        while (attempts.Count > 0 && now - attempts.Peek() >= 60000) attempts.Dequeue();
        if (!manual && attempts.Count >= 3) return null;
        long scheduled = Math.Max(now, (lastScheduled ?? (now - 2000)) + 2000);
        lastScheduled = scheduled;
        if (!manual) attempts.Enqueue(scheduled);
        return checked((int)(scheduled - now));
    }

    internal static bool Trusted(string? source, int port)
    {
        if (port < 1024 || port > 65535 || source is null) return false;
        // Compare the serialized URI too: do not accept URI-normalized aliases,
        // encoded paths, credentials, alternate host spellings or query strings.
        string origin = "http://127.0.0.1:" + port;
        return source == origin + "/" || source == origin + "/index.html";
    }

    internal static string? Command(string json)
    {
        if (json.Length > 256) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            var fields = new Dictionary<string, string>();
            foreach (var field in doc.RootElement.EnumerateObject())
                if (field.Value.ValueKind != JsonValueKind.String || !fields.TryAdd(field.Name, field.Value.GetString()!)) return null;
            if (fields.Count == 1 && fields.GetValueOrDefault("action") == "ready") return "ready";
            if (fields.Count == 2 && fields.GetValueOrDefault("action") == "reauthenticate"
                && fields.GetValueOrDefault("reason") is "authentication" or "retry") return fields["reason"];
        }
        catch (JsonException) { }
        return null;
    }
}
