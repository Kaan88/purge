namespace Purge.Client.Pipeline;

/// <summary>
/// The programs ticked for one "Uninstall N" click, run one after another through the Uninstall pipeline. Each keeps its
/// own confirmation, prompts and leftover step; the next one starts only when the user asks for it on the Uninstall page,
/// after the current one finished or was given up (declined, failed, not now), or it is skipped. No XAML here.
/// </summary>
public sealed class UninstallQueue
{
    private readonly List<UninstallTarget> _targets = [];
    private int _index = -1;

    /// <summary>The program the pipeline runs now; null when the queue is empty.</summary>
    public UninstallTarget? Current => _index >= 0 && _index < _targets.Count ? _targets[_index] : null;

    /// <summary>The program that follows <see cref="Current"/>; null at the last one.</summary>
    public UninstallTarget? Next => _index >= 0 && _index + 1 < _targets.Count ? _targets[_index + 1] : null;

    /// <summary>How many programs the click queued (skipped ones are no longer counted).</summary>
    public int Count => _targets.Count;

    /// <summary>The 1-based place of <see cref="Current"/>; 0 when the queue is empty.</summary>
    public int Position => Current is null ? 0 : _index + 1;

    /// <summary>True when more than one program was queued: the page says "2 of 3".</summary>
    public bool IsBatch => _targets.Count > 1;

    /// <summary>"2 of 3" for a batch, null for a single program.</summary>
    public string? PositionText => IsBatch && Current is not null ? $"{Position} of {Count}" : null;

    /// <summary>Starts a new queue (a program listed twice runs once) and returns its first program; null when empty.</summary>
    public UninstallTarget? Start(IEnumerable<UninstallTarget> targets)
    {
        _targets.Clear();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        _targets.AddRange(targets.Where(t => seen.Add(t.ProgramId)));
        _index = _targets.Count > 0 ? 0 : -1;
        return Current;
    }

    /// <summary>Moves on to <see cref="Next"/> and returns it; at the end the queue is empty and this returns null.</summary>
    public UninstallTarget? Advance()
    {
        if (Current is null) return null;
        _index++;
        if (_index < _targets.Count) return Current;
        Clear();
        return null;
    }

    /// <summary>Takes <see cref="Next"/> out of the queue without running it; returns the skipped program.</summary>
    public UninstallTarget? SkipNext()
    {
        if (Next is not { } next) return null;
        _targets.RemoveAt(_index + 1);
        return next;
    }

    /// <summary>Forgets the queue.</summary>
    public void Clear()
    {
        _targets.Clear();
        _index = -1;
    }
}
