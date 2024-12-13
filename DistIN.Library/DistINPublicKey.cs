using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINPublicKey : DistINObject
    {
        public string Identity { get; set; } = string.Empty;
        public string Key { get; set; } = string.Empty;
        public DistINKeyAlgorithm Algorithm { get; set; } = DistINKeyAlgorithm.DILITHIUM;
        public DateTime Date { get; set; } = DateTime.Now;
        public string Signature { get; set; } = string.Empty;

        public static DistINPublicKey Generate(string id, out string privateKey, DistINKeyAlgorithm algorithm)
        {
            DistINPublicKey key = new DistINPublicKey();
            key.Identity = id;
            key.Algorithm = algorithm;
            key.Date = DateTime.UtcNow;
            DistINKeyPair keyPair = CryptHelper.GenerateKeyPair(algorithm);
            key.Key = keyPair.PublicKey;
            privateKey = keyPair.PrivateKey;

            return key;
        }
    }
}
