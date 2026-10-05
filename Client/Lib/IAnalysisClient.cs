using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CSOToolbox.Client.Lib
{
    public interface IAnalysisClient : IDisposable
    {
        event Action<string, string, string, object?>? JobCompleted;
        void SetTimeout(int seconds);
        void Run(string jobId, AnalyzerType[] analyzers, string queryText, bool force = false, CancellationToken ct = default, IndicatorType indicatorType = IndicatorType.Unknown);
        Task<ServerHealthObject> CheckServerHealth(CancellationToken ct = default);
        Task<TunnelResponseV1?> QueryServiceAsync(AnalyzerType analyzer, string payload, bool force = false, CancellationToken ct = default, IndicatorType indicatorType = IndicatorType.Unknown);
    }
}
