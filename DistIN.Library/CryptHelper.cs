using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DistIN
{
    public static class CryptHelper
    {
        public const char KEY_PART_SEPARATOR = '|';

        /// <summary>
        /// Encodes a byte array to a URL-encoded base64 string.
        /// </summary>
        public static string EncodeUrlBase64(byte[] data)
        {
            return Convert.ToBase64String(data).Replace('/', '_').Replace('+', '-').Replace("=", "");
        }

        /// <summary>
        /// Decodes a URL-encoded base64 string to a byte array.
        /// </summary>
        public static byte[] DecodeUrlBase64(string data)
        {
            data = data.Replace('_', '/').Replace('-', '+');
            int trail = 4 - data.Length % 4;
            if (trail > 0 && trail < 4)
                data += new string('=', trail);
            return Convert.FromBase64String(data.Replace('_', '/').Replace('-', '+'));
        }


        public static string EncodeKey(params byte[][] parts)
        {
            List<string> strings = new List<string>();
            foreach (byte[] part in parts)
                strings.Add(EncodeUrlBase64(part));
            return string.Join(KEY_PART_SEPARATOR, strings);
        }
        public static List<byte[]> DecodeKey(string key)
        {
            List<byte[]> result = new List<byte[]>();
            foreach (string part in key.Split(KEY_PART_SEPARATOR))
                result.Add(DecodeUrlBase64(part));
            return result;
        }

        public static DistINKeyPair GenerateKeyPair(DistINKeyAlgorithm algorithm)
        {
            if (algorithm == DistINKeyAlgorithm.FALCON_512 || algorithm == DistINKeyAlgorithm.FALCON_1024)
            {
                FalconKeyPairGenerator generator = new FalconKeyPairGenerator();
                if (algorithm == DistINKeyAlgorithm.FALCON_512)
                    generator.Init(new FalconKeyGenerationParameters(new SecureRandom(), FalconParameters.falcon_512));
                else
                    generator.Init(new FalconKeyGenerationParameters(new SecureRandom(), FalconParameters.falcon_1024));

                AsymmetricCipherKeyPair cypherKeyPair = generator.GenerateKeyPair();
                FalconPrivateKeyParameters privateKey = (FalconPrivateKeyParameters)cypherKeyPair.Private;
                FalconPublicKeyParameters publicKey = (FalconPublicKeyParameters)cypherKeyPair.Public;

                DistINKeyPair keyPair = new DistINKeyPair();
                keyPair.Algorithm = DistINKeyAlgorithm.DILITHIUM;
                keyPair.PublicKey = EncodeKey(publicKey.GetEncoded());
                keyPair.PrivateKey = EncodeKey(privateKey.GetSpolyLittleF(), privateKey.GetG(), privateKey.GetSpolyBigF());

                return keyPair;
            }
            else if(algorithm == DistINKeyAlgorithm.KYBER)
            {
                KyberKeyPairGenerator generator = new KyberKeyPairGenerator();
                generator.Init(new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber1024));
                AsymmetricCipherKeyPair kyberKeyPair = generator.GenerateKeyPair();
                KyberPrivateKeyParameters privateKey = (KyberPrivateKeyParameters)kyberKeyPair.Private;
                KyberPublicKeyParameters publicKey = (KyberPublicKeyParameters)kyberKeyPair.Public;
                
                DistINKeyPair keyPair = new DistINKeyPair();
                keyPair.Algorithm = DistINKeyAlgorithm.KYBER;
                keyPair.PublicKey = EncodeKey(publicKey.GetT(), publicKey.GetRho());
                keyPair.PrivateKey = EncodeKey(privateKey.GetS(), privateKey.GetHpk(), privateKey.GetNonce(), privateKey.GetT(), privateKey.GetRho());

                return keyPair;
            }
            else
            {
                DilithiumKeyPairGenerator generator = new DilithiumKeyPairGenerator();
                generator.Init(new DilithiumKeyGenerationParameters(new SecureRandom(), DilithiumParameters.Dilithium5));

                AsymmetricCipherKeyPair cypherKeyPair = generator.GenerateKeyPair();
                DilithiumPrivateKeyParameters privateKey = (DilithiumPrivateKeyParameters)cypherKeyPair.Private;
                DilithiumPublicKeyParameters publicKey = (DilithiumPublicKeyParameters)cypherKeyPair.Public;

                DistINKeyPair keyPair = new DistINKeyPair();
                keyPair.Algorithm = DistINKeyAlgorithm.DILITHIUM;
                keyPair.PublicKey = EncodeKey(privateKey.Rho, privateKey.T1);
                keyPair.PrivateKey = EncodeKey(privateKey.K, privateKey.Tr, privateKey.S1, privateKey.S2, privateKey.T0);

                return keyPair;
            }
        }

        public static string SignData(DistINKeyPair keyPair, byte[] data)
        {
            if (keyPair.Algorithm == DistINKeyAlgorithm.FALCON_512)
            {
                List<byte[]> key = DecodeKey(keyPair.PrivateKey);
                FalconPrivateKeyParameters privKey = new FalconPrivateKeyParameters(FalconParameters.falcon_512, key[0], key[1], key[2], DecodeUrlBase64(keyPair.PublicKey));
                FalconSigner signer = new FalconSigner();
                signer.Init(true, privKey);

                return EncodeUrlBase64(signer.GenerateSignature(data));
            }
            else if (keyPair.Algorithm == DistINKeyAlgorithm.FALCON_1024)
            {
                List<byte[]> key = DecodeKey(keyPair.PrivateKey);
                FalconPrivateKeyParameters privKey = new FalconPrivateKeyParameters(FalconParameters.falcon_1024, key[0], key[1], key[2], DecodeUrlBase64(keyPair.PublicKey));
                FalconSigner signer = new FalconSigner();
                signer.Init(true, privKey);

                return EncodeUrlBase64(signer.GenerateSignature(data));
            }
            else
            {
                List<byte[]> pKey = DecodeKey(keyPair.PublicKey);
                List<byte[]> key = DecodeKey(keyPair.PrivateKey);
                DilithiumPrivateKeyParameters privKey = new DilithiumPrivateKeyParameters(DilithiumParameters.Dilithium5, pKey[0], key[0], key[1], key[2], key[3], key[4], pKey[1]);
                
                DilithiumSigner signer = new DilithiumSigner();
                signer.Init(true, privKey);
                
                return EncodeUrlBase64(signer.GenerateSignature(data));
            }
        }

        public static bool VerifySinature(DistINPublicKey publicKey, string signature, byte[] data)
        {
            return VerifySinature(publicKey.Algorithm, publicKey.Key, signature, data);
        }
        public static bool VerifySinature(DistINKeyAlgorithm algorithm, string publicKey, string signature, byte[] data)
        {
            byte[] sign = DecodeUrlBase64(signature);
            
            if(algorithm == DistINKeyAlgorithm.FALCON_512)
            {
                FalconPublicKeyParameters pubKey = new FalconPublicKeyParameters(FalconParameters.falcon_512, DecodeUrlBase64(publicKey));

                FalconSigner verifier = new FalconSigner();
                verifier.Init(false, pubKey);

                return verifier.VerifySignature(data, sign);
            }
            else if (algorithm == DistINKeyAlgorithm.FALCON_1024)
            {
                FalconPublicKeyParameters pubKey = new FalconPublicKeyParameters(FalconParameters.falcon_1024, DecodeUrlBase64(publicKey));

                FalconSigner verifier = new FalconSigner();
                verifier.Init(false, pubKey);

                return verifier.VerifySignature(data, sign);
            }
            else
            {
                List<byte[]> key = DecodeKey(publicKey);
                DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium5, key[0], key[1]);

                DilithiumSigner verifier = new DilithiumSigner();
                verifier.Init(false, pubKey);

                return verifier.VerifySignature(data, sign);
            }
        }


        public static string GenerateAndEncryptKyberAESKey(string publicKey, out byte[] aesKey)
        {
            List<byte[]> key = DecodeKey(publicKey);
            KyberPublicKeyParameters pk = new KyberPublicKeyParameters(KyberParameters.kyber1024, key[0], key[1]);

            var kemGenerator = new KyberKemGenerator(new SecureRandom());
            var secretWithEncapsulation = kemGenerator.GenerateEncapsulated(pk);
            aesKey = secretWithEncapsulation.GetSecret();

            return EncodeUrlBase64(secretWithEncapsulation.GetEncapsulation());
        }

        public static byte[] DecryptKyberAESKey(string privateKey, string encryptedAESKey)
        {
            List<byte[]> key = DecodeKey(privateKey);

            KyberPrivateKeyParameters sk =new KyberPrivateKeyParameters(KyberParameters.kyber1024, key[0], key[1], key[2], key[3], key[4]);

            var kemExtractor = new KyberKemExtractor(sk);
            return kemExtractor.ExtractSecret(DecodeUrlBase64(encryptedAESKey));
        }

        public static byte[] EncryptAES(byte[] data, byte[] keyBytes)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = keyBytes.Length * 8;
                aes.IV = new byte[aes.IV.Length];
                aes.Key = keyBytes;


                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] encryptedBytes;
                using (var stream = new System.IO.MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                    }
                    encryptedBytes = stream.ToArray();
                }
                return encryptedBytes;

                //return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            }
        }
        public static byte[] DecryptAES(byte[] data, byte[] keyBytes)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = keyBytes.Length * 8;
                aes.IV = new byte[aes.IV.Length];
                aes.Key = keyBytes;

                ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] decryptedBytes;
                using (var stream = new System.IO.MemoryStream(data))
                {
                    using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var msPlain = new System.IO.MemoryStream())
                        {
                            cryptoStream.CopyTo(msPlain);
                            decryptedBytes = msPlain.ToArray();
                        }
                    }
                }
                return decryptedBytes;

                //return aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
            }
        }
    }
}