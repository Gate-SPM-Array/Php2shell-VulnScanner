using System.Windows;
using System.Windows.Controls;
using PhpVulnScanner.Core;

namespace PhpVulnScanner.App;

/// <summary>
/// Traduzione dei testi scritti nello XAML: <c>l:Loc.Text="Avvia test"</c> e <c>l:Loc.Tip="Suggerimento"</c>.
/// Il testo italiano è la chiave, come per <c>L.T</c> nel codice; i test estraggono questi attributi dai file .xaml
/// e verificano che <c>lang/en.json</c> li traduca tutti.
/// </summary>
public static class Loc
{
    public static readonly DependencyProperty TextProperty =
        DependencyProperty.RegisterAttached("Text", typeof(string), typeof(Loc), new PropertyMetadata(null, OnText));

    public static readonly DependencyProperty TipProperty =
        DependencyProperty.RegisterAttached("Tip", typeof(string), typeof(Loc), new PropertyMetadata(null, OnTip));

    public static string? GetText(DependencyObject d) => (string?)d.GetValue(TextProperty);
    public static void SetText(DependencyObject d, string? value) => d.SetValue(TextProperty, value);
    public static string? GetTip(DependencyObject d) => (string?)d.GetValue(TipProperty);
    public static void SetTip(DependencyObject d, string? value) => d.SetValue(TipProperty, value);

    private static void OnText(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (e.NewValue is not string key) return;
        string s = L.Xaml(key);
        switch (d)
        {
            case Window w: w.Title = s; break;
            case HeaderedContentControl h: h.Header = s; break;      // TabItem, GroupBox
            case HeaderedItemsControl hi: hi.Header = s; break;      // MenuItem
            case ContentControl c: c.Content = s; break;             // Button, CheckBox, RadioButton, ComboBoxItem
            case TextBlock t: t.Text = s; break;
            case DataGridColumn col: col.Header = s; break;
        }
    }

    private static void OnTip(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (e.NewValue is string key && d is FrameworkElement fe) fe.ToolTip = L.Xaml(key);
    }
}
