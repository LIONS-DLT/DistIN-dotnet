using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN.Client
{
    public class DistINResponse<T>
    {
        public T? Result { get; set; }
        public byte[] ResultBinary { get; set; } = new byte[0];
        public string Signature {  get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public DistINServiceVerificationType ServiceVerificationType { get; set; } = DistINServiceVerificationType.DNS;

        public bool Verify(DistINPublicKey servicePublicKey)
        {
            return CryptHelper.VerifySinature(servicePublicKey, this.Signature, this.ResultBinary);
        }


    }
}
