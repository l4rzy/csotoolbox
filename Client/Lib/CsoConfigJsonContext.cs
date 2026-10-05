using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace CSOToolbox.Client.Lib;

[JsonSerializable(typeof(Dictionary<string, Dictionary<string, string>>))]
internal partial class CsoConfigJsonContext : JsonSerializerContext
{
}
