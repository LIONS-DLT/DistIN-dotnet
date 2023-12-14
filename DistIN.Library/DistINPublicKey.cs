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
    }
}
