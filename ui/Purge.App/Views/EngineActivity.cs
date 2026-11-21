using System.Diagnostics;
using System.Globalization;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>
/// Shows a running engine call on an info bar: the step it is on and the seconds spent in it and in all, updated once a
/// second, with the engine's last progress line underneath. Create it on the UI thread; dispose it when the call ends.
/// </summary>
internal sealed class EngineActivity : IDisposable
{
    private readonly InfoBar _bar;
    private readonly DispatcherQueueTimer _timer;
    private readonly Stopwatch _total = Stopwatch.StartNew();
    private readonly Stopwatch _step = Stopwatch.StartNew();
    private string _stepName;
    private string _line = "";

    public EngineActivity(InfoBar bar, string firstStep)
    {
        _bar = bar;
        _stepName = firstStep;
        Progress = new Progress<EngineProgress>(OnProgress);
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.Tick += (_, _) => Update();
        _timer.Start();
        Update();
    }

    /// <summary>Hand this to the engine call; it reports on the UI thread.</summary>
    public IProgress<EngineProgress> Progress { get; }

    /// <summary>The time since the call started.</summary>
    public TimeSpan Elapsed => _total.Elapsed;

    /// <summary>The step the call was on.</summary>
    public string StepName => _stepName;

    private void OnProgress(EngineProgress p)
    {
        if (p.IsStep)
        {
            _stepName = p.Text;
            _step.Restart();
            _line = "";
        }
        else
        {
            _line = Shorten(p.Text);
        }
        Update();
    }

    private void Update()
    {
        var step = Seconds(_step.Elapsed);
        var total = Seconds(_total.Elapsed);
        _bar.Title = $"{_stepName} · {step} s";
        var all = $"{total} s in all";
        _bar.Message = _line.Length > 0 ? $"{all} · {_line}" : all;
    }

    private static string Seconds(TimeSpan t) => ((long)t.TotalSeconds).ToString(CultureInfo.CurrentCulture);

    /// <summary>An engine progress line without its "[  1.234s] " prefix, cut to a readable length.</summary>
    public static string Shorten(string line)
    {
        var text = line.StartsWith('[') && line.IndexOf("] ", StringComparison.Ordinal) is var at and > 0 ? line[(at + 2)..] : line;
        return text.Length > 160 ? text[..157] + "…" : text;
    }

    public void Dispose()
    {
        _timer.Stop();
        _total.Stop();
        _step.Stop();
    }
}
