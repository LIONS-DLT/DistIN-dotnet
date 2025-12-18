using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;
using System.Text.Json;
using SimpleBase;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using System.Security.Cryptography.X509Certificates;

namespace DistIN.Application.Controllers
{
    public class DidController : Controller
    {
        // Route passend zu did:web:example.com:did:localid  ->  /did/localid/did.json
        // localid darf Punkte, Bindestriche etc. enthalten; mit catch-all auch weitere Segmente.
        [HttpGet("/did/{**localId}/did.json")]
        [Produces("application/did+json", "application/json")]
        public IActionResult GetDidDocument([FromRoute] string localId)
        {
            if (string.IsNullOrWhiteSpace(localId))
                return BadRequest("Missing localId.");

            // Falls URL-encoded (z.B. %40), hier dekodieren:
            localId = Uri.UnescapeDataString(localId);

            // Minimaler Schutz gegen Path-Tricks, falls du catch-all nutzt
            if (localId.Contains(".."))
                return BadRequest("Invalid localId.");

            var host = Request.Host.Value;                 // z.B. example.com
            var scheme = Request.Scheme;                   // http/https (hinter Proxy ggf. ForwardedHeaders nutzen)
            var did = $"did:web:{host}:did:{localId.Replace("/", ":")}";

            string identity = IDHelper.IDToIdentity(localId);
            DistINPublicKey? key = Database.PublicKeys.Where(
                string.Format("Identity='{0}' ORDER BY [Date] DESC", identity.ToSqlSafeValue())).FirstOrDefault();

            if(key == null)
                return NotFound();

            string keyString = "";
            if(key.Algorithm == DistINKeyAlgorithm.DILITHIUM)
            {
                List<byte[]> keyBytes = CryptHelper.DecodeKey(key.Key);
                DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium5, keyBytes[0], keyBytes[1]);
                keyString = ToPublicKeyMultibase(0x300011, pubKey.GetEncoded());
            }
            else if (key.Algorithm == DistINKeyAlgorithm.FALCON_512)
            {
                byte[] keyBytes = CryptHelper.DecodeUrlBase64(key.Key);
                keyString = ToPublicKeyMultibase(0x300001, keyBytes);
            }
            else if (key.Algorithm == DistINKeyAlgorithm.FALCON_1024)
            {
                byte[] keyBytes = CryptHelper.DecodeUrlBase64(key.Key);
                keyString = ToPublicKeyMultibase(0x300002, keyBytes);
            }

            var doc = new DidDocument
            {
                Context = new object[]
                {
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1"
                },
                Id = did,
                VerificationMethod = new[]
                {
                    new VerificationMethod
                    {
                        Id = $"{did}#sig-pqc",
                        Type = "Multikey",
                        Controller = did,
                        PublicKeyMultibase = keyString
                    }
                },
                Authentication = new[]
                {
                    $"{did}#sig-pqc"
                },
                AssertionMethod = new[]
                {
                    $"{did}#sig-pqc"
                }
            };

            Response.Headers.CacheControl = "public, max-age=60";

            var json = JsonSerializer.Serialize(doc, JsonOpts);
            return Content(json, "application/did+json");
        }

        [HttpGet("/.well-known/did.json")]
        [Produces("application/did+json", "application/json")]
        public IActionResult GetRootDidDocument()
        {
            var host = Request.Host.Value;
            var did = $"did:web:{host}";


            DistINKeyPair? key = AppConfig.Current.ServiceKeyPair;

            if (key == null)
                return NotFound();

            string keyString = "";
            if (key.Algorithm == DistINKeyAlgorithm.DILITHIUM)
            {
                List<byte[]> keyBytes = CryptHelper.DecodeKey(key.PublicKey);
                DilithiumPublicKeyParameters pubKey = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium5, keyBytes[0], keyBytes[1]);
                keyString = ToPublicKeyMultibase(0x300011, pubKey.GetEncoded());
            }
            else if (key.Algorithm == DistINKeyAlgorithm.FALCON_512)
            {
                byte[] keyBytes = CryptHelper.DecodeUrlBase64(key.PublicKey);
                keyString = ToPublicKeyMultibase(0x300001, keyBytes);
            }
            else if (key.Algorithm == DistINKeyAlgorithm.FALCON_1024)
            {
                byte[] keyBytes = CryptHelper.DecodeUrlBase64(key.PublicKey);
                keyString = ToPublicKeyMultibase(0x300002, keyBytes);
            }

            var doc = new DidDocument
            {
                Context = new object[] { "https://www.w3.org/ns/did/v1" },
                Id = did,
                VerificationMethod = new[]
                {
                    new VerificationMethod
                    {
                        Id = $"{did}#sig-pqc",
                        Type = "Multikey",
                        Controller = did,
                        PublicKeyMultibase = keyString
                    }
                },
                Authentication = new[]
                {
                    $"{did}#sig-pqc"
                },
                AssertionMethod = new[]
                {
                    $"{did}#sig-pqc"
                }
            };

            var json = JsonSerializer.Serialize(doc, JsonOpts);
            return Content(json, "application/did+json");
        }

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = true
        };

        // --- Minimal-DTOs fürs DID Document ---

        private sealed class DidDocument
        {
            [JsonPropertyName("@context")]
            public object[]? Context { get; set; }

            public string Id { get; set; } = default!;

            public VerificationMethod[]? VerificationMethod { get; set; }

            public string[]? Authentication { get; set; }

            public string[]? AssertionMethod { get; set; }
        }

        private sealed class VerificationMethod
        {
            public string Id { get; set; } = default!;
            public string Type { get; set; } = default!;
            public string Controller { get; set; } = default!;
            public string? PublicKeyMultibase { get; set; }
            public object? PublicKeyJwk { get; set; } // optional, falls du JWK nutzt
        }

        private const char MultibaseBase58Btc = 'z';

        public static string ToPublicKeyMultibase(uint multicodec, ReadOnlySpan<byte> rawPublicKey)
        {
            // 1) multicodec as unsigned varint
            byte[] codecVarint = EncodeUnsignedVarint(multicodec);

            // 2) concat(varint || keyBytes)
            byte[] prefixed = new byte[codecVarint.Length + rawPublicKey.Length];
            Buffer.BlockCopy(codecVarint, 0, prefixed, 0, codecVarint.Length);
            rawPublicKey.CopyTo(prefixed.AsSpan(codecVarint.Length));

            // 3) multibase base58btc: 'z' + base58btc(bytes)
            string b58 = Base58.Bitcoin.Encode(prefixed); // base58btc
            return MultibaseBase58Btc + b58;
        }

        // Unsigned varint (LEB128 style, MSB=continuation)
        private static byte[] EncodeUnsignedVarint(uint value)
        {
            var bytes = new List<byte>(5);
            while (value >= 0x80)
            {
                bytes.Add((byte)(value | 0x80));
                value >>= 7;
            }
            bytes.Add((byte)value);
            return bytes.ToArray();
        }
    }
}
