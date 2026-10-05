using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Primitives;
using Avalonia.Input.Platform;
using Microsoft.Extensions.Logging;
using CSOToolbox.Client.ViewModels;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        // ── Application state fields ──
        private CsoConfig _config = null!;
        private CsoState _state = null!;
        private CsoIndicatorExtractor _indicatorExtractor = null!;
        private IAnalysisClient _worker = null!;
        private CsoHistory _history = null!;
        private ILoggerFactory _loggerFactory = null!;
        private ILogger _logger = null!;
        private bool _isLogTabEnabled = false;

        private readonly ObservableCollection<HistoryRowViewModel> _historyViewModels = new();
        private readonly ObservableCollection<LogRowViewModel> _logViewModels = new();
        private readonly List<LogRowViewModel> _allLogs = new();
        private DispatcherTimer? _logFilterTimer;
        private DispatcherTimer? _dataFilterTimer;
        private bool _treeIsExpanded = false;

        private readonly object _pendingJobsLock = new();
        private readonly HashSet<string> _pendingJobIds = new();
        private CancellationTokenSource? _currentCts = null;
        private string? _currentSource = null;
        private string? _currentText = null;
        private object? _currentData = null;
        private DispatcherTimer? _updateTimer;

        private string? _pendingHistorySource = null;
        private string? _pendingHistoryText = null;
        private object? _pendingHistoryData = null;
        private string? _pendingAnalyzeText = null;
        private readonly HashSet<string> _historyRestoreJobIds = new();
        private List<string>? _cachedIndicatorList;
        private bool _notificationHovered;
        private DispatcherTimer? _notificationTimer;
        private bool _isWindowFocused = true;
        private bool _searchImagePasted;
        private string? _lastClipboardImageHash = null;
        private string? _lastCheckedClipboardText = null;
        private DateTime _lastClipboardCheckTime = DateTime.MinValue;
        private DispatcherTimer? _historyFilterTimer;
        private ClipboardMonitor? _clipboardMonitor;
        private CancellationTokenSource? _debounceCts;
        private DateTime _lastApiExecutionTime = DateTime.MinValue;
        private JsonDocument? _jsonDocument;
        private DateTime _workerStartTime;

        private readonly string[] WelcomeTexts = {
            "How are you doing today?",
            "Have you had your morning coffee or tea yet?",
            "Ctrl + L to quickly jump to Search Bar",
            "Ctrl + R to force refresh the Report tab"
        };

        private bool _isInitialized = false;

        private string NewJobId()
        {
            _currentCts?.Cancel();
            _currentCts?.Dispose();
            _currentCts = new CancellationTokenSource();

            lock (_pendingJobsLock)
            {
                _pendingJobIds.Clear();
                var id = Guid.NewGuid().ToString("N");
                _pendingJobIds.Add(id);
                return id;
            }
        }

        private readonly IAnalysisClient? _injectedWorker;

        public MainWindow() : this(null)
        {
        }

        public MainWindow(IAnalysisClient? worker)
        {
            _injectedWorker = worker;
            InitializeComponent();
            InitializeControls();
            _isInitialized = true;

            _listHistory.ItemsSource = _historyViewModels;
            _listHistory.DoubleTapped += OnHistoryListDoubleTapped;
            _listLog.ItemsSource = _logViewModels;

            InitializeApp();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        private void InitializeApp()
        {
            _loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddProvider(new LogTabLoggerProvider((compartment, message, level) =>
                {
                    if (!_isLogTabEnabled) return;
                    Dispatcher.UIThread.Post(() => AddLogRow(compartment, message, level));
                }));
                builder.SetMinimumLevel(LogLevel.Debug);
            });

            _logger = _loggerFactory.CreateLogger<MainWindow>();
            FormatHelpers.Logger = _logger;
            _config = new CsoConfig(GetConfigPath(), _loggerFactory.CreateLogger<CsoConfig>());
            _state = new CsoState(GetStatePath(), _loggerFactory.CreateLogger<CsoState>());
            _indicatorExtractor = new CsoIndicatorExtractor(_config, _loggerFactory.CreateLogger<CsoIndicatorExtractor>());
            _worker = _injectedWorker ?? new CsoWorker(_config, _loggerFactory.CreateLogger<CsoWorker>());
            _worker.SetTimeout(_config.GetBackendTimeout());
            _history = new CsoHistory(_config);
            _currentCts = new CancellationTokenSource();

            _logger.LogInformation("Application initialized");

            this.WindowStartupLocation = WindowStartupLocation.Manual;
            this.Width = _state.Width;
            this.Height = _state.Height;
            this.Position = new PixelPoint(_state.X, _state.Y);

            var searchBar = _txtSearchBar;
            if (searchBar != null)
            {
                searchBar.PlaceholderText = WelcomeTexts[Random.Shared.Next(WelcomeTexts.Length)];
            }

            this.Activated += OnWindowActivated;
            this.Activated += (s, e) =>
            {
                _isWindowFocused = true;
                StopBackgroundClipboardMonitor();
            };
            this.Deactivated += (s, e) =>
            {
                _isWindowFocused = false;
                StartBackgroundClipboardMonitor();
            };
            this.KeyDown += OnWindowKeyDown;
            _inAppToastNotification!.PointerPressed += (s, e) => DismissNotification();
            this.PositionChanged += OnWindowPositionChanged;
            this.PropertyChanged += OnWindowPropertyChanged;
            this.Closing += (s, e) =>
            {
                StopBackgroundClipboardMonitor();
                _currentCts?.Cancel();
                _currentCts?.Dispose();
                _currentCts = null;

                if (_config.GetKeepInTray())
                {
                    e.Cancel = true;
                    this.Hide();
                }
            };

            this.Closed += (s, e) =>
            {
                if (!_config.GetKeepInTray() && Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
                    desktop.Shutdown();
            };

            _worker.JobCompleted += OnWorkerJobCompleted;

            _isLogTabEnabled = _config.GetShowLogTab();
            if (_isLogTabEnabled)
                AddLogRow("system", "Log started");

            if (_config.GetAutoUpdate())
                StartAutoUpdateTimer();

            if (_config.GetKeepInTray())
                CreateTrayIcon();

            LoadPreferencesUI();
            UpdateNavButtons();

            Program.ArgumentsReceived += HandleReceivedArguments;

            // Handle initial arguments if any were passed to the process at start
            var initArgs = Environment.GetCommandLineArgs();
            if (initArgs.Length > 1)
            {
                var argsToProcess = new string[initArgs.Length - 1];
                Array.Copy(initArgs, 1, argsToProcess, 0, argsToProcess.Length);
                HandleReceivedArguments(argsToProcess);
            }
        }

        private void HandleReceivedArguments(string[] args)
        {
            Dispatcher.UIThread.Post(() =>
            {
                this.Show();
                if (this.WindowState == WindowState.Minimized)
                {
                    this.WindowState = WindowState.Normal;
                }
                this.Activate();
                this.Focus();

                foreach (var arg in args)
                {
                    if (arg.Contains("action=click") && arg.Contains("id="))
                    {
                        var parts = arg.Split(new[] { ';', '&' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var part in parts)
                        {
                            if (part.StartsWith("id="))
                            {
                                var id = part.Substring(3);
                                Helpers.NativeNotification.ExecuteCallback(id);
                            }
                        }
                    }
                }
            });
        }
    }
}
