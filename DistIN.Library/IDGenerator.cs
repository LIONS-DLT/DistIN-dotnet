using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public static class IDGenerator
    {
        private const string availableChars = "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        private static Random random = new Random();

        public static string GenerateRandomString(int length)
        {
            string result = "";
            for(int i = 0; i < length; i++)
            {
                result += availableChars[random.Next(0, availableChars.Length)];
            }
            return result;
        }

        public static string GenerateGUID()
        {
            return CryptHelper.EncodeUrlBase64(Guid.NewGuid().ToByteArray());
        }
        public static string GenerateStrongGUID()
        {
            return GenerateGUID() + GenerateRandomString(8);
        }
    }
}
