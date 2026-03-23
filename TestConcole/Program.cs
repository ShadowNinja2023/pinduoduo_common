using PddLib;

var api = new BackendApi("https://open-cdn.reverse-studio.com", "6d7f7522805a24f06f7534f1ecb306a7");
var result = await api.GetDeviceAsync();
var session = result.Results!.ParseSession();
var device = result.Results.ParseDevice();
var android = new Android(session, device);

Console.WriteLine("=== 请求商品详情，打印响应 ===");
var item = await android.GetItemDetailAsync("923425411993");
Console.WriteLine($"StatusCode: {item}");
