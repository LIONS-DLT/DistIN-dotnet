using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINKeyPair
    {
        public string PrivateKey { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
        public DistINKeyAlgorithm Algorithm { get; set; } = DistINKeyAlgorithm.DILITHIUM;
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum DistINKeyAlgorithm
    {
        DILITHIUM,
        FALCON_512,
        FALCON_1024,
        KYBER
    }
}
