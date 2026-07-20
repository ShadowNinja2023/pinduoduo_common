namespace PddLib.H5
{
    /// <summary>
    /// anti_content 真机基线 token —— 脱机 mock 的模板。
    ///
    /// 来源: 真机成功 render 请求抓包 (examples/compare/render/real.txt, 平板 TB322FC / Android 15,
    ///       render 出价成功)。解码结构见 docs/05_h5_web_crypto/07 (19 字段)。
    ///
    /// 用法: <see cref="AntiContentCodec.MintFromReal"/> 以此为模板, 刷新动态字段 (tag22 时间戳ms / tag9 秒时间戳),
    ///       可选覆盖 pdd_user_id(tag19)=当前会话 uid, 其余保留真机真实值 (nano_fp/audio/screen/UA/pdd_vds...)。
    ///
    /// ⚠ 这是"以真机值为基准的一定程度 mock", 非完整字段自造。整体构造 (canvas/nano_fp 算法/href 自洽等)
    ///   后续再做, 见 docs 07 §E。真机持久值 (pdd_user_id/pdd_vds/nano_fp) 与真机账号/设备绑定,
    ///   换账号可能需相应替换。
    /// </summary>
    public static class AntiContentBaseline
    {
        /// <summary>真机 render 成功请求的 anti_content (710 字符, 19 字段)。</summary>
        public const string RealToken =
            "0asWfqnFpioyj9vxknP4PpgU1UWNI1v9oirccirc96Ojg-ny5T-Dv5r76mNgUdsd8KrputvVTBf0TMfUD3NV4PR2vfXUPxN4aVK-wVeFl3a1EnR3xr1zOI-vhv-7kW0KFUYZLPe4_MQdEMqB_sMZpZngUNEV5Pt6Yof84FqANquqXjMnkS_67C1SXikcI12_buBVKpREMV0vZzDtUTf10IynBZeynpd3ABV5Ds1rT_-j3CK31lHBjio6A304FPDvZ7A_KIOLViFpsws1z_wW8coiQS6MqcJxzCSc3udq8rOkaSJaz6qVKWZt8I42t1c6OREWN0eDHt82aeMv1wB6kZY6oI5ueaXTAgF7DB4fX-re6Bx4bay0A-Y3HzbP7KP4yV6jAmZbtZi6bwNxF4pU7CfGZ5qGlAfGtIm_dvV_qPMqhKMwO2gaTtzTARAh2MdUV21g0Um-Ors-Ov4xZoNmNSrvaaZ1FOggRfp0ycgBdcgj1Mlz2zUPMXMtEp5ghkAKRoItP8Wx-GongxQ-InyA2KSYH0oQvQY6MHJLyBHyWXUpoKSHdrmRWLlU5ZwnwzoQIx1-JCHC6kagtzSF3-xnUV8FYKCPMnDIJyKCqqdUi3tUYrcpjydE0Dr5NfD8zbSEd5AkcaXlbclShAsSPA3bEWcIGha833-hrMAHNPaLUwclRRLEyHCqcNH-zdL7NKv-UWFN9d";
    }
}
