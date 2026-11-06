using Microsoft.Web.WebView2.WinForms;
using System.Security.AccessControl;
using System.Security.Principal;

namespace HopHarbor.Desktop;

internal sealed partial class PanelForm
{
    private bool fileDialogActive;

    private void ExportConfiguration(WebView2 view, long generation, string source, byte[] document)
    {
        if (fileDialogActive || !Visible || !CurrentDocument(view, generation, source)) return;
        fileDialogActive = true;
        // WebView2 event handlers must return before a modal dialog pumps messages.
        BeginInvoke(new Action(async () =>
        {
            string status = "cancelled";
            try
            {
                if (!CurrentDocument(view, generation, source) || !Visible) return;
                using var dialog = new SaveFileDialog
                {
                    Title = "Export HopHarbor configuration",
                    FileName = "HopHarbor-configuration.json",
                    Filter = "JSON configuration (*.json)|*.json",
                    DefaultExt = "json", AddExtension = true, OverwritePrompt = true,
                    CheckPathExists = true, RestoreDirectory = true
                };
                if (dialog.ShowDialog(this) == DialogResult.OK && CurrentDocument(view, generation, source))
                {
                    // A message supplies document bytes only. The chosen path stays
                    // native; write privately and atomically, never follow a link.
                    SaveConfiguration(dialog.FileName, document);
                    status = "saved";
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { status = "error"; }
            finally
            {
                fileDialogActive = false;
                if (CurrentDocument(view, generation, source))
                {
                    try { await view.CoreWebView2.ExecuteScriptAsync("window.dispatchEvent(new CustomEvent('hopharbor-file-result',{detail:{status:'" + status + "'}}))"); }
                    catch (Exception error) when (error is InvalidOperationException or System.Runtime.InteropServices.COMException) { }
                }
            }
        }));
    }

    private static void SaveConfiguration(string destination, byte[] document)
    {
        if (File.Exists(destination) && (File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("A configuration destination must be a regular file.");
        string temporary = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(destination))!, ".HopHarbor-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var permissions = new FileSecurity();
            permissions.SetAccessRuleProtection(true, false);
            permissions.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
            using (var stream = new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, permissions))
            {
                stream.Write(document);
                stream.Flush(true);
            }
            File.Move(temporary, destination, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
