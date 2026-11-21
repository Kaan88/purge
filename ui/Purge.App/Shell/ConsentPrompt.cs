using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Purge.App.Views;

namespace Purge.App.Shell;

public sealed record ConsentItem(string Path, LeftoverKind Kind, Band Band, string SizeText, long SizeBytes, bool IsUserData);

/// <summary>What the broker is asked to do: move into quarantine (the default), delete from it for good, or put back.</summary>
public enum ConsentAction { Quarantine, Delete, Restore }

public sealed record ConsentSummary(string AppName, IReadOnlyList<ConsentItem> Items, DateTime RestorableUntil,
    ConsentAction Action = ConsentAction.Quarantine);

/// <summary>
/// Preview of the security prompt ("7 · Security prompt (elevated)" artboard; ENGINE_PLAN.md §3.1 Consent, D3).
/// It is a plain Win32 TaskDialog on purpose. In M3 the elevated broker (<c>purge-engine --broker</c>) shows it, at
/// high integrity so programs without admin rights cannot click it; this preview runs it from the UI process so
/// the layout can be judged now. The confirm button stays disabled until the user ticks the review box whenever
/// user-data items are in the plan.
/// </summary>
public static unsafe partial class ConsentPrompt
{
    private const int MoveButtonId = 100;

    public static Task<bool> ShowAsync(nint owner, ConsentSummary summary)
    {
        var tcs = new TaskCompletionSource<bool>();
        var thread = new Thread(() =>
        {
            try { tcs.SetResult(Show(owner, summary)); }
            catch (Exception e) { tcs.SetException(e); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        return tcs.Task;
    }

    private static bool Show(nint owner, ConsentSummary s)
    {
        var n = s.Items.Count;
        var attention = s.Items.Where(i => i.IsUserData).ToList();
        var files = s.Items.Where(i => i.Kind == LeftoverKind.File).ToList();
        var reg = s.Items.Count(i => i.Kind == LeftoverKind.Registry);
        var tasks = s.Items.Count(i => i.Kind == LeftoverKind.Task);
        var ci = CultureInfo.CurrentCulture;

        var content = new StringBuilder();
        switch (s.Action)
        {
            case ConsentAction.Delete:
                content.Append("These items are in quarantine. Deleting them frees the space, and after that they can't be put back.\n\n");
                break;
            case ConsentAction.Restore:
                content.Append("Purge puts each item back where it was. Items whose place is now taken are skipped and listed.\n\n");
                break;
            default:
                content.Append("Purge built this list from its own scan. Everything can be put back from History & undo until ")
                    .Append(s.RestorableUntil.ToString("d MMM yyyy", ci)).Append(".\n\n");
                break;
        }
        if (files.Count > 0)
            content.Append("Files & folders: ").Append(files.Count).Append(" (").Append(ProgramRow.FormatSize(files.Sum(f => f.SizeBytes))).Append(")\n");
        if (reg > 0) content.Append("Registry keys and values: ").Append(reg).Append('\n');
        if (tasks > 0) content.Append("Scheduled tasks and services: ").Append(tasks).Append('\n');
        var safe = s.Items.Count(i => i.Band == Band.Safe);
        var other = n - safe;
        if (s.Action == ConsentAction.Quarantine)
        {
            content.Append("By rating: ").Append(safe).Append(" Safe");
            if (other > 0) content.Append(" · ").Append(other).Append(" you ticked yourself");
        }
        if (attention.Count > 0)
        {
            content.Append("\n\n⚠ Needs your attention (").Append(attention.Count).Append(")\n");
            foreach (var a in attention)
                content.Append(a.Path).Append("  ·  User data").Append(a.SizeText.Length > 0 ? " · " + a.SizeText : "").Append('\n');
        }

        var expanded = new StringBuilder();
        foreach (var i in s.Items)
            expanded.Append(i.IsUserData ? "⚠ " : "• ").Append(i.Path).Append(i.SizeText.Length > 0 ? "  (" + i.SizeText + ")" : "").Append('\n');

        var strings = new List<nint>();
        nint Str(string v) { var p = Marshal.StringToHGlobalUni(v); strings.Add(p); return p; }

        try
        {
            var button = new TaskDialogButton
            {
                Id = MoveButtonId,
                Text = Str(s.Action switch
                {
                    ConsentAction.Delete => n == 1 ? "Delete 1 item" : $"Delete {n} items",
                    ConsentAction.Restore => n == 1 ? "Put back 1 item" : $"Put back {n} items",
                    _ => n == 1 ? "Move 1 item to quarantine" : $"Move {n} items to quarantine",
                }),
            };
            var config = new TaskDialogConfig
            {
                cbSize = (uint)sizeof(TaskDialogConfig),
                hwndParent = owner,
                dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW,
                dwCommonButtons = TDCBF_CANCEL_BUTTON,
                pszWindowTitle = Str("Purge security prompt (preview)"),
                hMainIcon = TD_SHIELD_ICON,
                pszMainInstruction = Str(s.Action switch
                {
                    ConsentAction.Delete => $"Delete {n} quarantined items of {s.AppName} for good?",
                    ConsentAction.Restore => $"Put back {n} items of {s.AppName}?",
                    _ => $"Move {n} leftovers of {s.AppName} to quarantine?",
                }),
                pszContent = Str(content.ToString().TrimEnd()),
                cButtons = 1,
                pButtons = &button,
                nDefaultButton = TDCBF_CANCEL_ID,
                pszVerificationText = attention.Count > 0
                    ? Str(attention.Count == 1 ? "I reviewed the item marked ⚠" : "I reviewed the items marked ⚠")
                    : 0,
                pszExpandedInformation = Str(expanded.ToString().TrimEnd()),
                pszExpandedControlText = Str("Hide the items"),
                pszCollapsedControlText = Str($"See all {n} items"),
                hFooterIcon = TD_INFORMATION_ICON,
                pszFooter = Str("Preview shown by the window. In M3 the elevated helper shows this prompt, and only it can start the plan."),
                pfCallback = &Callback,
                lpCallbackData = attention.Count > 0 ? 1 : 0,
                cxWidth = 300,
            };
            int pressed = 0, radio = 0, verified = 0;
            var hr = TaskDialogIndirect(&config, &pressed, &radio, &verified);
            Marshal.ThrowExceptionForHR(hr);
            return pressed == MoveButtonId;
        }
        finally
        {
            foreach (var p in strings) Marshal.FreeHGlobal(p);
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static int Callback(nint hwnd, uint notification, nint wParam, nint lParam, nint refData)
    {
        if (refData == 0) return 0;
        switch (notification)
        {
            case TDN_CREATED:
                SendMessageW(hwnd, TDM_ENABLE_BUTTON, MoveButtonId, 0);
                break;
            case TDN_VERIFICATION_CLICKED:
                SendMessageW(hwnd, TDM_ENABLE_BUTTON, MoveButtonId, wParam != 0 ? 1 : 0);
                break;
        }
        return 0;
    }

    private const uint TDF_ALLOW_DIALOG_CANCELLATION = 0x0008;
    private const uint TDF_POSITION_RELATIVE_TO_WINDOW = 0x1000;
    private const uint TDCBF_CANCEL_BUTTON = 0x0008;
    private const int TDCBF_CANCEL_ID = 2;
    private const nint TD_SHIELD_ICON = 0xFFFC;        // MAKEINTRESOURCEW(-4)
    private const nint TD_INFORMATION_ICON = 0xFFFD;   // MAKEINTRESOURCEW(-3)
    private const uint TDN_CREATED = 0;
    private const uint TDN_VERIFICATION_CLICKED = 8;
    private const uint TDM_ENABLE_BUTTON = 0x0400 + 111;

    // commctrl.h declares the task dialog structs inside pshpack1.h.
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct TaskDialogButton
    {
        public int Id;
        public nint Text;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct TaskDialogConfig
    {
        public uint cbSize;
        public nint hwndParent;
        public nint hInstance;
        public uint dwFlags;
        public uint dwCommonButtons;
        public nint pszWindowTitle;
        public nint hMainIcon;
        public nint pszMainInstruction;
        public nint pszContent;
        public uint cButtons;
        public TaskDialogButton* pButtons;
        public int nDefaultButton;
        public uint cRadioButtons;
        public nint pRadioButtons;
        public int nDefaultRadioButton;
        public nint pszVerificationText;
        public nint pszExpandedInformation;
        public nint pszExpandedControlText;
        public nint pszCollapsedControlText;
        public nint hFooterIcon;
        public nint pszFooter;
        public delegate* unmanaged[Stdcall]<nint, uint, nint, nint, nint, int> pfCallback;
        public nint lpCallbackData;
        public uint cxWidth;
    }

    [LibraryImport("comctl32.dll")]
    private static partial int TaskDialogIndirect(TaskDialogConfig* config, int* button, int* radio, int* verified);

    [LibraryImport("user32.dll")]
    private static partial nint SendMessageW(nint hwnd, uint msg, nint wParam, nint lParam);
}
