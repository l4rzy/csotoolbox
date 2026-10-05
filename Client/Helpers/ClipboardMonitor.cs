using System;
using System.Threading;
using System.Threading.Tasks;

namespace CSOToolbox.Client.Helpers
{
    /// <summary>
    /// Polls a caller-provided clipboard reader and raises an event when its text changes.
    /// The caller controls when monitoring starts and stops.
    /// </summary>
    public class ClipboardMonitor
    {
        public event EventHandler<string>? ClipboardTextChanged;

        private readonly Func<Task<string?>> _readClipboardText;
        private bool _isRunning;
        private CancellationTokenSource? _cts;

        public ClipboardMonitor(Func<Task<string?>> readClipboardText)
        {
            _readClipboardText = readClipboardText;
        }

        public void Start()
        {
            if (_isRunning) return;
            _isRunning = true;

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            Task.Run(() => MonitorClipboardAsync(token), token);
        }

        public void Stop()
        {
            if (!_isRunning) return;
            _isRunning = false;

            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
        }

        private async Task MonitorClipboardAsync(CancellationToken ct)
        {
            string? lastText = null;
            try
            {
                lastText = await _readClipboardText();
                if (lastText != null) lastText = lastText.Trim();
            }
            catch
            {
                // Best-effort: clipboard read failed, continue polling
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(1000, ct);

                    var currentText = await _readClipboardText();
                    if (currentText != null)
                    {
                        currentText = currentText.Trim();
                        if (currentText != lastText)
                        {
                            lastText = currentText;
                            if (!string.IsNullOrEmpty(currentText))
                            {
                                OnClipboardTextChanged(currentText);
                            }
                        }
                    }
                    else
                    {
                        lastText = null;
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ClipboardMonitor] Polling worker error: {ex.Message}");
                }
            }
        }

        protected virtual void OnClipboardTextChanged(string text)
        {
            ClipboardTextChanged?.Invoke(this, text);
        }
    }
}
