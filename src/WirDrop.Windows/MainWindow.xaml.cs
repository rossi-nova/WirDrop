using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using WirDrop.Core.AirDrop;
using WirDrop.Core.Net;
using WirDrop.Windows.Services;
using WirDrop.Windows.Views;

namespace WirDrop.Windows;

public partial class MainWindow : Window
{
    private readonly AirDropService _service = new();
    private readonly List<string> _pendingDrop = [];

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _service;
        InterfaceCombo.ItemsSource = _service.Interfaces();
        InterfaceCombo.SelectedIndex = 0;
        Loaded += OnLoaded;
        Closing += OnClosing;
        _service.AskRequested += OnAskRequested;
        _service.SendProgress += OnSendProgress;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await _service.StartAsync(InterfaceCombo.SelectedItem as NetworkInterfaceInfo);
            SetRunning(true);
        }
        catch (Exception ex)
        {
            _service.AddLog($"启动失败：{ex.Message}");
            SetRunning(false);
        }
    }

    private void SetRunning(bool running)
    {
        StatusText.Text = running ? $"已开启 · 端口 {(_service.Interface is null ? "-" : "8771")}" : "未启动";
        ToggleButton.Content = running ? "停止" : "启动";
    }

    private async void ToggleButton_Click(object sender, RoutedEventArgs e)
    {
        ToggleButton.IsEnabled = false;
        try
        {
            if (_service.IsRunning)
            {
                await _service.StopAsync();
                SetRunning(false);
            }
            else
            {
                await _service.StartAsync(InterfaceCombo.SelectedItem as NetworkInterfaceInfo);
                SetRunning(true);
            }
        }
        catch (Exception ex)
        {
            _service.AddLog($"操作失败：{ex.Message}");
        }
        finally
        {
            ToggleButton.IsEnabled = true;
        }
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_service.DownloadDirectory);
        Process.Start(new ProcessStartInfo("explorer.exe", _service.DownloadDirectory) { UseShellExecute = true });
    }

    private void Window_DragEnter(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] paths)
        {
            return;
        }

        _pendingDrop.Clear();
        _pendingDrop.AddRange(paths);
        var peers = _service.Peers.Count;
        if (peers == 0)
        {
            _service.AddLog($"收到 {paths.Length} 个待发送项，但没有发现任何设备");
            return;
        }

        var peer = PeersList.SelectedItem as PeerViewModel ?? _service.Peers[0];
        await SendToAsync(peer, paths);
    }

    private async void PeersList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (PeersList.SelectedItem is not PeerViewModel peer)
        {
            return;
        }

        var dialog = new Microsoft.Win32.OpenFileDialog { Multiselect = true, Title = $"发送给 {peer.ServiceId}" };
        if (dialog.ShowDialog(this) == true)
        {
            await SendToAsync(peer, dialog.FileNames);
        }
    }

    private async void PeersList_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && PeersList.SelectedItem is PeerViewModel peer)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog { Multiselect = true, Title = $"发送给 {peer.ServiceId}" };
            if (dialog.ShowDialog(this) == true)
            {
                await SendToAsync(peer, dialog.FileNames);
            }
        }
    }

    private async Task SendToAsync(PeerViewModel peer, IReadOnlyList<string> paths)
    {
        if (!_service.IsRunning)
        {
            _service.AddLog("请先启动服务");
            return;
        }

        await _service.SendAsync(peer, paths);
    }

    private void OnAskRequested(object? sender, IncomingAsk ask)
    {
        Dispatcher.InvokeAsync(() =>
        {
            var dialog = new ReceivePromptWindow(ask) { Owner = this.IsVisible ? this : null };
            dialog.ShowDialog();
        });
    }

    private void OnSendProgress(object? sender, (long Sent, long Total) p)
    {
        Dispatcher.InvokeAsync(() =>
        {
            StatusText.Text = $"发送中 {p.Sent * 100 / Math.Max(1, p.Total)}%";
        });
    }

    private async void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        await _service.DisposeAsync();
    }
}