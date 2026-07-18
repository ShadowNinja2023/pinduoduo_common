using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace PddLib.H5
{
    /// <summary>
    /// H5 web 加密客户端 —— 通过常驻 Node 服务 (scripts/h5_tools/h5_service.js) 调用:
    ///   - anti_content  (PDD web 风控 token, react_anti_co chunk, jsdom 运行)
    ///   - csr_risk_token + AES key/iv (react_goods 的 Qre VM 的 lie())
    ///   - encrypt_info 解密 (AES-256-CBC/Pkcs7, key/iv 来自 lie)
    ///
    /// 说明: anti_content 采集面巨大 + csr 是自定义字节码 VM, 纯 C# 复刻不现实,
    ///       故走 Node 常驻服务 + 行式 JSON-RPC (stdin/stdout)。进程内预热, 复用。
    ///
    /// 验证状态: anti_content 离线生成已实测过风控通过; csr/AES 方案坐实 (AES-256-CBC 往返一致),
    ///           端到端 encrypt_info 解密待测 (服务端非总是返回加密数据)。
    /// </summary>
    public sealed class H5CryptoClient : IDisposable
    {
        private readonly Process _proc;
        private readonly StreamWriter _stdin;
        private readonly ConcurrentDictionary<int, TaskCompletionSource<JsonElement>> _pending = new();
        private readonly TaskCompletionSource<bool> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _idSeq = 0;
        private volatile bool _disposed;

        /// <param name="serviceJsPath">h5_service.js 的完整路径</param>
        /// <param name="nodeExe">node 可执行文件 (默认 "node", 依赖 PATH)</param>
        public H5CryptoClient(string serviceJsPath, string nodeExe = "node")
        {
            if (!File.Exists(serviceJsPath))
                throw new FileNotFoundException("找不到 h5_service.js", serviceJsPath);

            var psi = new ProcessStartInfo
            {
                FileName = nodeExe,
                Arguments = "\"" + serviceJsPath + "\"",
                WorkingDirectory = Path.GetDirectoryName(serviceJsPath)!,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _proc.OutputDataReceived += OnStdout;
            _proc.ErrorDataReceived += (_, __) => { /* 忽略 chunk 内部日志 */ };
            _proc.Start();
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();
            _stdin = _proc.StandardInput;
        }

        /// <summary>等待服务预热完成 (加载 3MB bundle + jsdom, 约 15~30s)。</summary>
        public Task WaitReadyAsync(TimeSpan? timeout = null)
        {
            var t = timeout ?? TimeSpan.FromSeconds(60);
            return Task.WhenAny(_ready.Task, Task.Delay(t)).ContinueWith(x =>
            {
                if (!_ready.Task.IsCompleted) throw new TimeoutException("H5 服务预热超时");
            });
        }

        private void OnStdout(object sender, DataReceivedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(e.Data)) return;
            JsonElement root;
            try { root = JsonDocument.Parse(e.Data).RootElement; }
            catch { return; } // 非 JSON 行 (理论上不应出现, 服务已把 console 重定向到 stderr)

            if (root.TryGetProperty("event", out var ev))
            {
                if (ev.GetString() == "ready") _ready.TrySetResult(true);
                else if (ev.GetString() == "error") _ready.TrySetException(new Exception(root.GetProperty("error").GetString()));
                return;
            }
            if (root.TryGetProperty("id", out var idEl) && idEl.TryGetInt32(out var id) && _pending.TryRemove(id, out var tcs))
            {
                if (root.TryGetProperty("ok", out var ok) && ok.GetBoolean())
                    tcs.TrySetResult(root.GetProperty("result").Clone());
                else
                    tcs.TrySetException(new Exception(root.TryGetProperty("error", out var er) ? er.GetString() : "unknown error"));
            }
        }

        private async Task<JsonElement> RpcAsync(object req, TimeSpan? timeout = null)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(H5CryptoClient));
            int id = Interlocked.Increment(ref _idSeq);
            var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pending[id] = tcs;
            var payload = JsonSerializer.Serialize(new RpcEnvelope(id, req));
            lock (_stdin) { _stdin.Write(payload); _stdin.Write('\n'); _stdin.Flush(); }
            var winner = await Task.WhenAny(tcs.Task, Task.Delay(timeout ?? TimeSpan.FromSeconds(30)));
            if (winner != tcs.Task) { _pending.TryRemove(id, out _); throw new TimeoutException("H5 RPC 超时"); }
            return await tcs.Task;
        }

        /// <summary>生成 anti_content。env = 真机浏览器指纹 (见 env_real.json 结构); null 用默认。</summary>
        public async Task<string> GetAntiContentAsync(object? env = null)
        {
            var r = await RpcAsync(new { cmd = "anti", env });
            return r.GetString()!;
        }

        /// <summary>生成 {csr_risk_token, rawKey, rawIV}。rawKey/rawIV 留作 encrypt_info 解密。</summary>
        public async Task<KeyIvCsr> GetKeyIvCsrAsync()
        {
            var r = await RpcAsync(new { cmd = "keyivcsr" });
            return new KeyIvCsr(
                r.GetProperty("csr_risk_token").GetString()!,
                r.GetProperty("rawKey").GetString()!,
                r.GetProperty("rawIV").GetString()!);
        }

        /// <summary>用 rawKey/rawIV 解密响应 encrypt_info (AES-256-CBC)。</summary>
        public async Task<string?> DecryptEncryptInfoAsync(string encryptInfo, string rawKey, string rawIV)
        {
            var r = await RpcAsync(new { cmd = "decrypt", encInfo = encryptInfo, rawKey, rawIV });
            return r.ValueKind == JsonValueKind.Null ? null : r.GetString();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { if (!_proc.HasExited) _proc.Kill(true); } catch { }
            try { _proc.Dispose(); } catch { }
        }

        public readonly record struct KeyIvCsr(string CsrRiskToken, string RawKey, string RawIV);

        private sealed class RpcEnvelope
        {
            public int id { get; }
            [JsonExtensionData] public System.Collections.Generic.Dictionary<string, JsonElement> Extra { get; }
            public RpcEnvelope(int id, object req)
            {
                this.id = id;
                var el = JsonSerializer.SerializeToElement(req);
                Extra = new();
                foreach (var p in el.EnumerateObject()) Extra[p.Name] = p.Value.Clone();
            }
        }
    }
}
