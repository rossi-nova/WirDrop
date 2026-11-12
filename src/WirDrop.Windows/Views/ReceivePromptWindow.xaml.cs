using System.Windows;
using WirDrop.Core.AirDrop;

namespace WirDrop.Windows.Views;

public partial class ReceivePromptWindow : Window
{
    private readonly IncomingAsk _ask;

    public ReceivePromptWindow(IncomingAsk ask)
    {
        _ask = ask;
        InitializeComponent();
        FromText.Text = $"发送方：{ask.Request.SenderComputerName}";
        if (ask.Request.IsLinkShare)
        {
            FromText.Text += " · 链接分享";
        }

        foreach (var file in ask.Request.Files)
        {
            FilesList.Items.Add(file.FileName);
        }

        foreach (var url in ask.Request.Items)
        {
            FilesList.Items.Add(url);
        }
    }

    private void AcceptButton_Click(object sender, RoutedEventArgs e)
    {
        _ask.Decision.TrySetResult(true);
        Close();
    }

    private void DeclineButton_Click(object sender, RoutedEventArgs e)
    {
        _ask.Decision.TrySetResult(false);
        Close();
    }
}
