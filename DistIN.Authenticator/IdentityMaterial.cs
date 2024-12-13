using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN.Authenticator
{
    public class IdentityMaterial : DistINObject
    {
        public const string FILE_EXTENSIONS = ".distin";

        public DistINKeyPair KeyPair { get; set; } = new DistINKeyPair();
        public string Password { get; set; } = string.Empty;


        public void Save()
        {
            Save(this.Password);
        }
        public void Save(string password)
        {
            this.Password = password;

            string filename = Uri.EscapeDataString(this.ID) + FILE_EXTENSIONS;
            string filepath = Path.Combine(FileSystem.Current.AppDataDirectory, filename);

            byte[] key = CryptHelper.CalculateHash_256(Encoding.UTF8.GetBytes(password));

            byte[] data = Encoding.UTF8.GetBytes(this.ToJsonString());
            data = CryptHelper.EncryptAES(data, key);

            File.WriteAllBytes(filepath, data);
        }

        public static List<string> GetLocalIDs()
        {
            List<string> list = new List<string>();

            foreach (string filepath in Directory.GetFiles(FileSystem.Current.AppDataDirectory))
            {
                string filename = Path.GetFileName(filepath);
                if (filename.EndsWith(FILE_EXTENSIONS))
                {
                    list.Add(Uri.UnescapeDataString(filename.Substring(0, filename.Length - FILE_EXTENSIONS.Length)));
                }
            }

            return list;
        }

        public static IdentityMaterial Open(string id, string password)
        {
            try
            {
                string filename = Uri.EscapeDataString(id) + FILE_EXTENSIONS;
                string filepath = Path.Combine(FileSystem.Current.AppDataDirectory, filename);

                byte[] key = CryptHelper.CalculateHash_256(Encoding.UTF8.GetBytes(password));
                byte[] data = File.ReadAllBytes(filepath);
                data = CryptHelper.DecryptAES(data, key);

                return DistINObject.FromJsonString<IdentityMaterial>(Encoding.UTF8.GetString(data));
            }
            catch (Exception ex)
            {
                throw new Exception("Invalid password.");
            }
        }

        public static IdentityMaterial Create(string id, DistINKeyAlgorithm algorithm, string password)
        {
            IdentityMaterial material = new IdentityMaterial();
            material.ID = id;
            material.KeyPair = DistINKeyPair.Generate(algorithm);
            material.Password = password;
            material.Save();
            return material;
        }
    }
}
