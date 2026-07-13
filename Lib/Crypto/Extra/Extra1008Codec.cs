using System.Text;

namespace PddLib.Crypto.Extra;

/// <summary>
/// PDD user_env2.extra (1008) 容器编解码。
///
/// 容器布局 (两种分帧变体, 见 ParseFraming):
///   [0:6]   magic (0f c1 00 00 10 08)
///   [6:10]  lenflag
///   [10:12] 0x4279
///   [12:16] nonce (由时间戳派生)
///   标准变体: [16:18] counter, body 从 18 起, 两个 KEY 索引标记都在 body 内
///   _d 变体:  [16:20] word0 标记(00 i0 i1 i2), [20:22] counter, body 从 22 起, word1 标记在 body 内
///   body: 加密主体 = 明文 ⊕ keystream, 中间夹 4B KEY 索引标记 (00||i0||i1||i2);
///         keystream 连续跨过标记 (标记字节不参与 XOR)。
///
/// 解密: 从两组索引查 KeyTable 得 KEY_8B → 组 seed → keystream = G(seed) → 连续密文 ⊕ keystream。
/// </summary>
public sealed class Extra1008Codec
{
    public const int HeaderLen = 18;

    private readonly KeyTable _keyTable;
    private readonly IKeystreamGenerator _ksGen;

    public Extra1008Codec(KeyTable keyTable, IKeystreamGenerator ksGen)
    {
        _keyTable = keyTable;
        _ksGen = ksGen;
    }

    public sealed record DecryptResult(
        byte[] Nonce, byte[] Counter, byte[] Key8, byte[] Seed,
        byte[] Keystream, byte[] Plaintext)
    {
        public string PlaintextUtf8 => Encoding.UTF8.GetString(Plaintext);
    }

    /// <summary>
    /// 解密容器 (显式给标记偏移)。markerOffsets = 两组 KEY 索引标记的字节偏移 (各 4B)。
    /// word0IsSecondMarker: 容器里索引顺序 (标记出现顺序 = word0‖word1, 即默认 false)。
    /// </summary>
    public DecryptResult Decrypt(byte[] raw, int[] markerOffsets, bool word0IsSecondMarker = false)
    {
        if (raw.Length < HeaderLen) throw new ArgumentException("容器太短");
        if (markerOffsets.Length != 2) throw new ArgumentException("需要 2 组索引标记偏移");

        var nonce = raw[12..16];
        var counter = raw[16..18];

        var idxA = Index3.FromMarker(raw.AsSpan(markerOffsets[0], 4)); // 前一个标记
        var idxB = Index3.FromMarker(raw.AsSpan(markerOffsets[1], 4)); // 后一个标记
        var word0Idx = word0IsSecondMarker ? idxB : idxA;
        var word1Idx = word0IsSecondMarker ? idxA : idxB;

        var key8 = _keyTable.DeriveKey8(word0Idx, word1Idx);
        var seed = Seed.Build(nonce, counter, key8);

        var cipher = ExtractContinuousCipher(raw, markerOffsets);
        var ks = _ksGen.Generate(seed, cipher.Length);

        var pt = new byte[cipher.Length];
        for (int i = 0; i < cipher.Length; i++) pt[i] = (byte)(cipher[i] ^ ks[i]);

        return new DecryptResult(nonce, counter, key8, seed, ks, pt);
    }

    /// <summary>取加密主体的连续密文 (从 bodyStart 起, 跳过各 4B 索引标记, 标记不参与 keystream)。</summary>
    public static byte[] ExtractContinuousCipher(byte[] raw, IEnumerable<int> skipMarkerOffsets, int bodyStart = HeaderLen)
    {
        var skip = new HashSet<int>();
        foreach (var off in skipMarkerOffsets)
            for (int j = 0; j < 4; j++) skip.Add(off + j);

        var body = new List<byte>(raw.Length);
        for (int p = bodyStart; p < raw.Length; p++)
            if (!skip.Contains(p)) body.Add(raw[p]);
        return body.ToArray();
    }

    /// <summary>
    /// 容器分帧信息。两种变体:
    ///   标准(_b/_t): nonce@12:16, counter@16:18, body@18, 两个 KEY 标记都在 body。
    ///   _d 变体:     nonce 后@16 紧跟 word0 标记(00 i0 i1 i2), counter 后移到@20:22, body@22。
    /// </summary>
    public sealed record Framing(byte[] Nonce, byte[] Counter, int BodyStart, int HeaderWord0Pos);

    /// <summary>解析容器头, 自动识别是否为 _d 变体 (nonce 后紧跟 KEY 索引标记)。</summary>
    public static Framing ParseFraming(byte[] raw)
    {
        var nonce = raw[12..16];
        if (raw[16] == 0x00 && raw[17] <= 8 && raw[18] <= 15)   // _d 变体: 头部标记@16
            return new Framing(nonce, raw[20..22], 22, 16);
        return new Framing(nonce, raw[16..18], 18, -1);
    }

    /// <summary>
    /// 全自动解密: 解析分帧 → 扫描 KEY 索引标记 → 查表得 KEY_8B → 生成 keystream → 连续 XOR。
    /// 对候选(标记配对 × word 顺序)按前 96B 可打印率择优, 无需人工给偏移。
    /// 覆盖 _b / _d / _t / user_env2 全部变体。
    /// </summary>
    public DecryptResult DecryptAuto(byte[] raw)
    {
        // 优先走 lenflag 确定性解码 (5 样本坐实); 可打印率高即采用, 否则回退启发式扫描。
        try
        {
            var byLf = DecryptByLenflag(raw);
            if (PrintableRatio(byLf.Plaintext, 96) > 0.95) return byLf;
        }
        catch { /* lenflag 指向无效 → 回退启发式 */ }

        var f = ParseFraming(raw);
        var bodyMarks = ScanCandidateMarkers(raw, f.BodyStart);

        DecryptResult? best = null; double bestScore = -1;
        void Try(Index3 w0, Index3 w1, int[] skip)
        {
            byte[] key8, seed, ks;
            try { key8 = _keyTable.DeriveKey8(w0, w1); }
            catch { return; }
            seed = Seed.Build(f.Nonce, f.Counter, key8);
            var cipher = ExtractContinuousCipher(raw, skip, f.BodyStart);
            try { ks = _ksGen.Generate(seed, cipher.Length); }
            catch { return; }
            var pt = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++) pt[i] = (byte)(cipher[i] ^ ks[i]);
            double score = PrintableRatio(pt, 96);
            if (score > bestScore) { bestScore = score; best = new DecryptResult(f.Nonce, f.Counter, key8, seed, ks, pt); }
        }

        if (f.HeaderWord0Pos >= 0)
        {
            // word0 在头部@16; word1 是 body 内某个标记; XOR 只跳 body 标记
            var w0 = Index3.FromMarker(raw.AsSpan(f.HeaderWord0Pos, 4));
            foreach (var wm in bodyMarks)
            {
                var w1 = Index3.FromMarker(raw.AsSpan(wm, 4));
                Try(w0, w1, new[] { wm });
                Try(w1, w0, new[] { wm });
            }
        }
        else
        {
            // 两个 KEY 标记都在 body; XOR 跳这两个
            for (int i = 0; i < bodyMarks.Count; i++)
                for (int j = i + 1; j < bodyMarks.Count; j++)
                {
                    var a = Index3.FromMarker(raw.AsSpan(bodyMarks[i], 4));
                    var b = Index3.FromMarker(raw.AsSpan(bodyMarks[j], 4));
                    Try(a, b, new[] { bodyMarks[i], bodyMarks[j] });
                    Try(b, a, new[] { bodyMarks[i], bodyMarks[j] });
                }
        }

        if (best is null) throw new InvalidOperationException("未找到可用的 KEY 索引标记, 无法解密");
        return best;
    }

    // ==================== 基于 lenflag 的确定性编解码 ====================
    //
    // ★ lenflag(容器[6:10]) = 两组 KEY 索引标记的定位指针 (5 样本坐实):
    //     lenflag[6:8] = BE16(word0 标记偏移 - 10)
    //     lenflag[8:10] = BE16(word1 标记偏移 - 10)
    //   偏移相对 0x4279(@10) 起算。word0/word1 与标记在容器里的先后无关 (lenflag 直接指明谁是 word0)。
    //   服务端据此定位标记、查表得 KEY_8B, 无需启发式扫描。故 mock 必须让 lenflag 与实际标记位一致。

    /// <summary>由 lenflag 读出的分帧 (确定性): word0/word1 标记偏移 + counter + body 起点。</summary>
    public sealed record LenflagFraming(byte[] Nonce, byte[] Counter, int BodyStart, int Word0MarkerOffset, int Word1MarkerOffset);

    /// <summary>解析 lenflag 得确定性分帧。</summary>
    public static LenflagFraming ParseLenflag(byte[] raw)
    {
        int w0off = ((raw[6] << 8) | raw[7]) + 10;
        int w1off = ((raw[8] << 8) | raw[9]) + 10;
        var nonce = raw[12..16];
        // _d 变体: 某个标记落在 nonce 之后@16 (在 counter 之前) → counter 后移到@20:22, body@22
        bool dVariant = w0off == 16 || w1off == 16;
        var counter = dVariant ? raw[20..22] : raw[16..18];
        int bodyStart = dVariant ? 22 : 18;
        return new LenflagFraming(nonce, counter, bodyStart, w0off, w1off);
    }

    /// <summary>基于 lenflag 的确定性解密 (不做启发式猜测; 推荐)。</summary>
    public DecryptResult DecryptByLenflag(byte[] raw)
    {
        var f = ParseLenflag(raw);
        var w0 = Index3.FromMarker(raw.AsSpan(f.Word0MarkerOffset, 4));
        var w1 = Index3.FromMarker(raw.AsSpan(f.Word1MarkerOffset, 4));
        var key8 = _keyTable.DeriveKey8(w0, w1);
        var seed = Seed.Build(f.Nonce, f.Counter, key8);

        var skip = new List<int>();
        if (f.Word0MarkerOffset >= f.BodyStart) skip.Add(f.Word0MarkerOffset);
        if (f.Word1MarkerOffset >= f.BodyStart) skip.Add(f.Word1MarkerOffset);

        var cipher = ExtractContinuousCipher(raw, skip, f.BodyStart);
        var ks = _ksGen.Generate(seed, cipher.Length);
        var pt = new byte[cipher.Length];
        for (int i = 0; i < cipher.Length; i++) pt[i] = (byte)(cipher[i] ^ ks[i]);
        return new DecryptResult(f.Nonce, f.Counter, key8, seed, ks, pt);
    }

    // ==================== 编码 (mock 反向组包) ====================

    private static readonly byte[] Magic = { 0x0f, 0xc1, 0x00, 0x00, 0x10, 0x08 };

    /// <summary>索引 → 4 字节标记 00||i0||i1||i2。</summary>
    public static byte[] MarkerBytes(Index3 idx) => new[] { (byte)0x00, (byte)idx.I0, (byte)idx.I1, (byte)idx.I2 };

    private static void WriteBE16(byte[] b, int off, ushort v) { b[off] = (byte)(v >> 8); b[off + 1] = (byte)v; }

    /// <summary>
    /// 编码容器 (Encrypt/DecryptByLenflag 互逆)。给定明文 + nonce/counter + 两组 KEY 索引 + 两个标记的容器偏移。
    /// 标记偏移相对容器起点; 若某偏移==16 则为 _d 变体(该标记置于 nonce 后、counter 前, body@22), 否则标准(body@18)。
    /// 通常由 DecryptByLenflag 的分帧回填偏移以做逐字节往返; mock 用 EncryptMock 自动选位。
    /// </summary>
    public byte[] Encrypt(byte[] plaintext, byte[] nonce4, byte[] counter2,
        Index3 word0Idx, Index3 word1Idx, int word0MarkerOffset, int word1MarkerOffset)
    {
        if (nonce4.Length != 4) throw new ArgumentException("nonce 必须 4 字节");
        if (counter2.Length != 2) throw new ArgumentException("counter 必须 2 字节");

        var key8 = _keyTable.DeriveKey8(word0Idx, word1Idx);
        var seed = Seed.Build(nonce4, counter2, key8);
        var ks = _ksGen.Generate(seed, plaintext.Length);

        bool dVariant = word0MarkerOffset == 16 || word1MarkerOffset == 16;
        int bodyStart = dVariant ? 22 : 18;

        // 分类标记: @16 的进 header, 其余进 body
        var bodyMarkers = new SortedDictionary<int, byte[]>();
        int headerMarkerOff = -1; byte[]? headerMarkerBytes = null;
        void Place(int off, byte[] mb)
        {
            if (off == 16) { headerMarkerOff = off; headerMarkerBytes = mb; }
            else if (off >= bodyStart) bodyMarkers[off] = mb;
            else throw new ArgumentException($"标记偏移 {off} 落在 header 内 (只允许 ==16 或 >= {bodyStart})");
        }
        Place(word0MarkerOffset, MarkerBytes(word0Idx));
        Place(word1MarkerOffset, MarkerBytes(word1Idx));

        int total = bodyStart + plaintext.Length + 4 * bodyMarkers.Count;
        var outp = new byte[total];

        // header
        Magic.CopyTo(outp, 0);
        WriteBE16(outp, 6, (ushort)(word0MarkerOffset - 10));
        WriteBE16(outp, 8, (ushort)(word1MarkerOffset - 10));
        outp[10] = 0x42; outp[11] = 0x79;
        nonce4.CopyTo(outp, 12);
        if (dVariant)
        {
            headerMarkerBytes!.CopyTo(outp, 16);   // word* 标记 @16
            counter2.CopyTo(outp, 20);
        }
        else counter2.CopyTo(outp, 16);

        // body: 连续 XOR, 在指定偏移插入 4B 标记 (不消费 keystream)
        int ki = 0, p = bodyStart;
        while (p < total)
        {
            if (bodyMarkers.TryGetValue(p, out var mb)) { mb.CopyTo(outp, p); p += 4; }
            else { outp[p] = (byte)(plaintext[ki] ^ ks[ki]); ki++; p++; }
        }
        if (ki != plaintext.Length) throw new InvalidOperationException($"标记偏移与明文长度不一致 (消费 {ki}/{plaintext.Length})");
        return outp;
    }

    /// <summary>
    /// mock 便捷编码: 标准变体, word0 标记在前、word1 在后, 分别插在明文第 p0/p1 字节处 (ks 索引)。
    /// 不给 p0/p1 时默认放在约 1/3、2/3 处。服务端靠 lenflag 定位标记, 位置可自由选择。
    /// </summary>
    public byte[] EncryptMock(byte[] plaintext, byte[] nonce4, byte[] counter2,
        Index3 word0Idx, Index3 word1Idx, int? p0 = null, int? p1 = null)
    {
        int n = plaintext.Length;
        int a = p0 ?? n / 3;
        int b = p1 ?? (2 * n) / 3;
        a = Math.Clamp(a, 0, n);
        b = Math.Clamp(b, a, n);
        int word0Off = bodyStartStandard + a;         // word0 标记在前
        int word1Off = bodyStartStandard + b + 4;      // word1 在后 (前面已插 1 个 4B 标记)
        return Encrypt(plaintext, nonce4, counter2, word0Idx, word1Idx, word0Off, word1Off);
    }

    private const int bodyStartStandard = 18;

    private static double PrintableRatio(byte[] b, int n)
    {
        int lim = Math.Min(n, b.Length);
        if (lim == 0) return 0;
        int ok = 0;
        for (int i = 0; i < lim; i++)
            if ((b[i] >= 32 && b[i] < 127) || b[i] == 9 || b[i] == 10 || b[i] == 13) ok++;
        return (double)ok / lim;
    }

    /// <summary>
    /// 启发式扫描候选索引标记 (00||i0||i1||i2, i0∈[0,8] i1∈[0,15])。
    /// 生产中标记偏移随样本变化, 这里给个辅助定位; 命中多个时结合结构判断。
    /// </summary>
    public static List<int> ScanCandidateMarkers(byte[] raw, int start = HeaderLen)
    {
        var hits = new List<int>();
        for (int p = start; p + 4 <= raw.Length; p++)
            if (raw[p] == 0x00 && raw[p + 1] <= 8 && raw[p + 2] <= 15)
                hits.Add(p);
        return hits;
    }

    public static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\n", "").Trim();
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
        return b;
    }
}
