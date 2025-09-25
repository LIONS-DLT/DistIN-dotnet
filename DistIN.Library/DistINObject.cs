using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DistIN
{
    public abstract class DistINObject : JsonSerializableObject
    {
        //public static JsonSerializerOptions JsonSerializerOptions { get; private set; } = new JsonSerializerOptions()
        //{
        //    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        //    PropertyNameCaseInsensitive = true,
        //    WriteIndented = true // TODO: remove for production
        //};

        [PropertyIsPrimaryKey]
        public virtual string ID { get; set; } = IDGenerator.GenerateGUID();

        //public string ToJsonString()
        //{
        //    return JsonSerializer.Serialize(this, this.GetType(), JsonSerializerOptions);
        //}
        //public static T FromJsonString<T>(string json)
        //{
        //    return JsonSerializer.Deserialize<T>(json, JsonSerializerOptions)!;
        //}
    }

    public abstract class JsonSerializableObject
    {
        public static JsonSerializerOptions JsonSerializerOptions { get; private set; } = new JsonSerializerOptions()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true // TODO: remove for production
        };

        public string ToJsonString()
        {
            return JsonSerializer.Serialize(this, this.GetType(), JsonSerializerOptions);
        }
        public static T FromJsonString<T>(string json)
        {
            return JsonSerializer.Deserialize<T>(json, JsonSerializerOptions)!;
        }
    }
}
