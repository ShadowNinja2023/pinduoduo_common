namespace PddLib.Crypto.Extra;

/// <summary>
/// keystream 生成器抽象。给定 16 字节 seed, 生成任意长度 keystream。
///
/// 这是整个算法里唯一"难"的部分 (G 函数, OLLVM 混淆的非线性分组流密码)。
/// 落地方式:
///   1) UnicornKeystreamGenerator —— 用 Unicorn 引擎执行 libdyncommon 的真实 G 代码
///      (跟随真实控制流, 对任意 KEY/nonce 全块正确)。【生产用】
///   2) StaticKeystreamGenerator —— 喂预先 dump 的 keystream, 仅用于跑通/验证上层编解码链路。
///
/// 上层 Extra1008Codec 只依赖本接口, 换实现无需改动。
/// </summary>
public interface IKeystreamGenerator
{
    /// <summary>生成 nBytes 字节 keystream (seed = 4279|nonce|counter|KEY_8B)。</summary>
    byte[] Generate(byte[] seed16, int nBytes);
}
