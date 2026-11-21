using Purge.App.Views;

namespace Purge.App;

/// <summary>How much Purge pre-selects in leftover reviews (board 17, "safety dial").</summary>
public enum SafetyPreset { Cautious, Balanced, Thorough }

/// <summary>
/// UI settings for this preview, kept in memory only (persisting them is M3 work, ENGINE_PLAN.md §9.4 S5).
/// Nothing here reaches the engine: presets decide which boxes start ticked in the UI and never loosen the engine's
/// guard or deny lists.
/// </summary>
public static class Settings
{
    public static SafetyPreset Preset { get; set; } = SafetyPreset.Balanced;

    /// <summary>"Pre-select user data": off by default; only the user can turn it on, no preset does.</summary>
    public static bool PreSelectUserData { get; set; }

    public static event Action? Changed;

    public static void RaiseChanged() => Changed?.Invoke();

    /// <summary>
    /// Whether a candidate starts ticked. Protected and Weak are never ticked for you; user data only when the user
    /// turned on "Pre-select user data" (S19), whatever the preset.
    /// </summary>
    public static bool PreSelects(SafetyPreset preset, Band band, bool isUserData)
    {
        if (band is Band.Protected or Band.Weak) return false;
        if (isUserData && !PreSelectUserData) return false;
        return preset switch
        {
            SafetyPreset.Cautious => false,
            SafetyPreset.Balanced => band == Band.Safe,
            _ => band is Band.Safe or Band.Likely,
        };
    }
}
