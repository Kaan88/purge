using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>
/// One program in the footprint map (board 09): its installed size plus what it is expected to leave behind
/// (<c>programs.forecast</c>, proposed). Also the row of the list fallback.
/// </summary>
public sealed partial class FootprintItem
{
    public FootprintItem(string name, string sub, Brush tile, string initial, long size, LeftoverForecast? forecast, ProgramRow? row, int count = 1)
    {
        Name = name;
        Sub = sub;
        // Own brush per block, so nothing done to the Programs list tiles carries over.
        Tile = tile is SolidColorBrush s ? new SolidColorBrush(s.Color) : tile;
        Initial = initial;
        SizeBytes = size;
        Forecast = forecast;
        Row = row;
        Count = count;
    }

    public string Name { get; }
    public string Sub { get; }
    public Brush Tile { get; }
    public string Initial { get; }
    public long SizeBytes { get; }
    public LeftoverForecast? Forecast { get; }
    public ProgramRow? Row { get; }
    public int Count { get; }

    public long LeftoverBytes => Forecast?.EstimateBytes ?? 0;
    public double Area => SizeBytes + LeftoverBytes;
    public double LeftoverShare => Area > 0 ? LeftoverBytes / Area : 0;

    public string SizeText => ProgramRow.FormatSize(SizeBytes);
    public string LeftoverText => Forecast switch
    {
        null => "Not known yet",
        { Verdict: ForecastVerdict.Clean } => "Clean",
        { EstimateBytes: { } b } f => "~" + ProgramRow.FormatSize(b) + (f.What is { } w ? " " + w : ""),
        _ => "Some, size not known",
    };
    public string BandText => Forecast?.EstimateBytes is { } b ? $"~{ProgramRow.FormatSize(b)} left" : "";
    public string AccessName => $"{Name}, {SizeText} installed, expected leftovers: {LeftoverText}";

    // Layout (set by the treemap)
    public Thickness Margin { get; set; }
    public double Width { get; set; }
    public double Height { get; set; }
    public double BandHeight => Height * LeftoverShare;
    /// <summary>Diagonal lines filling the band, clipped to it (a fresh geometry per element).</summary>
    public Geometry Hatch
    {
        get
        {
            var group = new GeometryGroup();
            double w = Width, h = BandHeight, step = 8;
            // Lines x + y = c for c in (0, w + h), clipped to the w×h rectangle.
            for (var c = step; c < w + h; c += step)
            {
                var x0 = Math.Max(0, c - h); var y0 = c - x0;
                var x1 = Math.Min(w, c); var y1 = c - x1;
                group.Children.Add(new LineGeometry { StartPoint = new Windows.Foundation.Point(x0, y0), EndPoint = new Windows.Foundation.Point(x1, y1) });
            }
            return group;
        }
    }

    public Visibility BandVisibility => LeftoverShare > 0 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility BandLabelVisibility => BandHeight >= 20 && Width >= 70 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility LabelVisibility => Width >= 56 && Height - BandHeight >= 34 ? Visibility.Visible : Visibility.Collapsed;

    // List fallback bar (0–200 px of the largest)
    public double ListBar { get; set; }
    public double ListBand => ListBar * LeftoverShare;
    public Thickness ListBandMargin => new(ListBar - ListBand, 0, 0, 0);
}

/// <summary>Squarified treemap (Bruls, Huizing, van Wijk). Deterministic for the same input.</summary>
public static class Treemap
{
    public static void Layout(IReadOnlyList<FootprintItem> items, double width, double height, double gap = 4)
    {
        var total = items.Sum(i => i.Area);
        if (total <= 0 || width <= 0 || height <= 0) return;
        var scale = width * height / total;
        var queue = new Queue<FootprintItem>(items.OrderByDescending(i => i.Area));
        double x = 0, y = 0, w = width, h = height;
        while (queue.Count > 0)
        {
            var side = Math.Min(w, h);
            var row = new List<FootprintItem>();
            double rowArea = 0;
            while (queue.Count > 0)
            {
                var next = queue.Peek().Area * scale;
                if (row.Count == 0 || Worst(row, rowArea + next, next, side, scale) <= Worst(row, rowArea, 0, side, scale))
                {
                    row.Add(queue.Dequeue());
                    rowArea += next;
                }
                else break;
            }
            if (w >= h)
            {
                var colW = rowArea / h;
                double cy = y;
                foreach (var i in row)
                {
                    var ih = i.Area * scale / colW;
                    Place(i, x, cy, colW, ih, gap);
                    cy += ih;
                }
                x += colW; w -= colW;
            }
            else
            {
                var rowH = rowArea / w;
                double cx = x;
                foreach (var i in row)
                {
                    var iw = i.Area * scale / rowH;
                    Place(i, cx, y, iw, rowH, gap);
                    cx += iw;
                }
                y += rowH; h -= rowH;
            }
        }
    }

    private static double Worst(List<FootprintItem> row, double sum, double extra, double side, double scale)
    {
        if (sum <= 0) return double.MaxValue;
        var areas = row.Select(r => r.Area * scale).ToList();
        if (extra > 0) areas.Add(extra);
        var max = areas.Max();
        var min = areas.Min();
        var s2 = side * side;
        return Math.Max(s2 * max / (sum * sum), sum * sum / (s2 * min));
    }

    private static void Place(FootprintItem i, double x, double y, double w, double h, double gap)
    {
        i.Margin = new Thickness(x, y, 0, 0);
        i.Width = Math.Max(0, w - gap);
        i.Height = Math.Max(0, h - gap);
    }
}
