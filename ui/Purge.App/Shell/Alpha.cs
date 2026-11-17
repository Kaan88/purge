using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Shell;

/// <summary>
/// The UI alpha (branch ui-alpha): scan and review only. Every button that would change the PC (uninstall, move to
/// quarantine, undo, resume, roll back, delete) is disabled with <see cref="Tooltip"/>; the M3 broker brings them.
/// </summary>
public static class Alpha
{
    /// <summary>True in this build. A static field, not a const, so the disabled paths still compile without warnings.</summary>
    public static readonly bool On = true;

    /// <summary>The tooltip of every disabled action.</summary>
    public const string Tooltip = "Coming in M3";

    /// <summary>What the alpha does, for notices.</summary>
    public const string Note = "This alpha scans and reviews only; nothing on the PC is changed.";

    /// <summary>
    /// Disables a control and gives it the alpha tooltip (no-op when the alpha is off). A disabled control shows no
    /// tooltip, so XAML wraps such buttons in a transparent Border that carries it.
    /// </summary>
    public static void Disable(Control control)
    {
        if (!On) return;
        control.IsEnabled = false;
        ToolTipService.SetToolTip(control, Tooltip);
    }

}
