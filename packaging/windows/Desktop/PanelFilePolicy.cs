using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HopHarbor.Desktop;

// Pure parsing rules are exercised on the build host as well as Windows.
internal static class PanelFilePolicy
{
    internal const int MaxBytes = 262144;
    internal static bool OfficialLink(string? value) => value is not null
        && Regex.IsMatch(value, @"\Ahttps://github\.com/kiyanibehzad/HopHarbor(?:/?|/releases/?|/releases/tag/v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6})\z");

    internal static byte[]? ExportDocument(string json)
    {
        if (json.Length > MaxBytes + 128) return null;
        try
        {
            using var message = JsonDocument.Parse(json);
            var root = message.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            var fields = new HashSet<string>();
            foreach (var field in root.EnumerateObject()) if (!fields.Add(field.Name)) return null;
            if (fields.Count != 2 || !root.TryGetProperty("action", out var action)
                || action.ValueKind != JsonValueKind.String || action.GetString() != "exportConfiguration"
                || !root.TryGetProperty("document", out var document) || document.ValueKind != JsonValueKind.Object
                || !document.TryGetProperty("format", out var format) || format.ValueKind != JsonValueKind.String
                || format.GetString() != "HopHarbor configuration") return null;
            byte[] bytes = Encoding.UTF8.GetBytes(document.GetRawText() + "\n");
            return bytes.Length <= MaxBytes ? bytes : null;
        }
        catch (JsonException) { return null; }
    }
}
