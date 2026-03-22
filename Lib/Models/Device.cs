using System.Text.Json.Serialization;

namespace PddLib.Models
{
    /// <summary>
    /// 设备信息（对应 GetDevice 返回的 device）
    /// </summary>
    public class Device
    {
        [JsonPropertyName("imei")]
        public string Imei { get; set; } = string.Empty;

        [JsonPropertyName("oaid")]
        public string Oaid { get; set; } = string.Empty;

        [JsonPropertyName("brand")]
        public string Brand { get; set; } = string.Empty;

        [JsonPropertyName("model")]
        public string Model { get; set; } = string.Empty;

        [JsonPropertyName("pixels")]
        public string Pixels { get; set; } = string.Empty;

        [JsonPropertyName("deviceInfo")]
        public DeviceInfo? DeviceInfo { get; set; }
    }

    /// <summary>
    /// 设备详细信息
    /// </summary>
    public class DeviceInfo
    {
        [JsonPropertyName("build")]
        public BuildInfo? Build { get; set; }

        [JsonPropertyName("ro.product.name")]
        public string? ProductName { get; set; }

        [JsonPropertyName("ro.boot.hardware")]
        public string? BootHardware { get; set; }

        [JsonPropertyName("ro.product.board")]
        public string? ProductBoard { get; set; }

        [JsonPropertyName("ro.product.brand")]
        public string? ProductBrand { get; set; }

        [JsonPropertyName("ro.product.model")]
        public string? ProductModel { get; set; }

        [JsonPropertyName("ro.product.device")]
        public string? ProductDevice { get; set; }

        [JsonPropertyName("ro.product.cpu.abi")]
        public string? CpuAbi { get; set; }

        [JsonPropertyName("gsm.version.baseband")]
        public string? GsmBaseband { get; set; }

        [JsonPropertyName("gsm.version.ril-impl")]
        public string? GsmRilImpl { get; set; }

        [JsonPropertyName("ro.build.version.sdk")]
        public string? SdkVersion { get; set; }

        [JsonPropertyName("ro.product.manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("ro.build.version.release")]
        public string? VersionRelease { get; set; }

        [JsonPropertyName("ro.build.version.security_patch")]
        public string? SecurityPatch { get; set; }

        [JsonPropertyName("Version")]
        public string? Version { get; set; }
    }

    /// <summary>
    /// Android Build 信息
    /// </summary>
    public class BuildInfo
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("host")]
        public string? Host { get; set; }

        [JsonPropertyName("tags")]
        public string? Tags { get; set; }

        [JsonPropertyName("time")]
        public long Time { get; set; }

        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("user")]
        public string? User { get; set; }

        [JsonPropertyName("board")]
        public string? Board { get; set; }

        [JsonPropertyName("brand")]
        public string? Brand { get; set; }

        [JsonPropertyName("model")]
        public string? Model { get; set; }

        [JsonPropertyName("device")]
        public string? Device { get; set; }

        [JsonPropertyName("serial")]
        public string? Serial { get; set; }

        [JsonPropertyName("display")]
        public string? Display { get; set; }

        [JsonPropertyName("product")]
        public string? Product { get; set; }

        [JsonPropertyName("hardware")]
        public string? Hardware { get; set; }

        [JsonPropertyName("socModel")]
        public string? SocModel { get; set; }

        [JsonPropertyName("bootloader")]
        public string? Bootloader { get; set; }

        [JsonPropertyName("fingerprint")]
        public string? Fingerprint { get; set; }

        [JsonPropertyName("manufacturer")]
        public string? Manufacturer { get; set; }

        [JsonPropertyName("supportedAbis")]
        public string? SupportedAbis { get; set; }

        [JsonPropertyName("sku")]
        public string? Sku { get; set; }

        [JsonPropertyName("odmSku")]
        public string? OdmSku { get; set; }
    }
}
