using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DistIN
{
    public class DistINToken
    {
        public byte[] HeaderData { get; set; } = new byte[0];
        public byte[] PayloadData { get; set; } = new byte[0];
        public byte[] SignatureData { get; set; } = new byte[0];


        public void SetHeader(DistINTokenHeader header)
        {
            this.HeaderData = header.ToByteArray();
        }
        public DistINTokenHeader GetHeader()
        {
            return DistINTokenHeader.FromByteArray(this.HeaderData);
        }

        public void SetPayload(DistINTokenPayload payload)
        {
            this.PayloadData = payload.ToByteArray();
        }
        public DistINTokenPayload GetPayload()
        {
            return DistINTokenPayload.FromByteArray(this.PayloadData);
        }

        public static DistINToken Create(DistINTokenPayload payload, DistINKeyPair keyPair)
        {
            DistINToken token = new DistINToken();
            token.SetHeader(new DistINTokenHeader()
            {
                Algorithm = keyPair.Algorithm
            });

            token.SetPayload(payload);

            string encodedString = CryptHelper.EncodeUrlBase64(token.HeaderData) + "." + CryptHelper.EncodeUrlBase64(token.PayloadData);

            token.SignatureData = CryptHelper.DecodeUrlBase64(CryptHelper.SignData(keyPair, Encoding.UTF8.GetBytes(encodedString)));

            return token;
        }

        public DistINTokenValidationResult Validate(DistINPublicKey publicKey, string? subject = null)
        {
            return Validate(publicKey, DateTime.UtcNow, subject);
        }
        public DistINTokenValidationResult Validate(DistINPublicKey publicKey, DateTime validationTime, string? subject)
        {
            if (!VerifySignature(publicKey))
                return DistINTokenValidationResult.Invalid_Signature;

            DistINTokenPayload payload = this.GetPayload();

            if (payload.GetExpirationTime() < validationTime)
                return DistINTokenValidationResult.Expired;

            if (payload.GetNotBefore() > validationTime)
                return DistINTokenValidationResult.Not_Yet_Valid;

            if (!string.IsNullOrEmpty(subject))
            {
                if (payload.Subject != subject)
                    return DistINTokenValidationResult.Invalid_Subject;
            }

            return DistINTokenValidationResult.Success;
        }

        public bool VerifySignature(DistINPublicKey publicKey)
        {
            string encodedString = CryptHelper.EncodeUrlBase64(this.HeaderData) + "." + CryptHelper.EncodeUrlBase64(this.PayloadData);

            return CryptHelper.VerifySinature(publicKey, CryptHelper.EncodeUrlBase64(this.SignatureData), Encoding.UTF8.GetBytes(encodedString));
        }

        public static DistINToken FromString(string value)
        {
            string[] parts = value.Split('.');

            DistINToken token = new DistINToken();

            token.HeaderData = CryptHelper.DecodeUrlBase64(parts[0]);
            token.PayloadData = CryptHelper.DecodeUrlBase64(parts[1]);
            token.SignatureData = CryptHelper.DecodeUrlBase64(parts[2]);

            return token;
        }

        public override string ToString()
        {
            return CryptHelper.EncodeUrlBase64(this.HeaderData) + "." + CryptHelper.EncodeUrlBase64(this.PayloadData) + "." + CryptHelper.EncodeUrlBase64(this.SignatureData);
        }
    }

    public class DistINTokenHeader
    {
        [JsonPropertyName("typ")]
        public string Type { get; set; } = "jwt";

        //[JsonPropertyName("cty")]
        //public string ContentType { get; set; } = string.Empty;

        [JsonPropertyName("alg")]
        public DistINKeyAlgorithm Algorithm { get; set; } = DistINKeyAlgorithm.DILITHIUM;

        public string ToJsonString()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
            });
        }
        public override string ToString()
        {
            return CryptHelper.EncodeUrlBase64(Encoding.UTF8.GetBytes(this.ToJsonString()));
        }

        public static DistINTokenHeader FromString(string headerString)
        {
            byte[] data = CryptHelper.DecodeUrlBase64(headerString);
            string json = Encoding.UTF8.GetString(data);
            return JsonSerializer.Deserialize<DistINTokenHeader>(json, new JsonSerializerOptions()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
            })!;
        }

        public byte[] ToByteArray()
        {
            return Encoding.UTF8.GetBytes(this.ToJsonString());
        }
        public static DistINTokenHeader FromByteArray(byte[] headerData)
        {
            string json = Encoding.UTF8.GetString(headerData);
            return JsonSerializer.Deserialize<DistINTokenHeader>(json, new JsonSerializerOptions()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
            })!;
        }
    }

    public class DistINTokenPayload
    {

        [JsonPropertyName("iss")]
        public string Issuer { get; set; } = string.Empty;

        [JsonPropertyName("sub")]
        public string Subject { get; set; } = string.Empty;

        [JsonPropertyName("aud")]
        public string Audience { get; set; } = string.Empty;

        [JsonPropertyName("exp")]
        public long ExpirationTimeUnix { get; set; } = 0;

        [JsonPropertyName("nbf")]
        public long NotBeforeUnix { get; set; } = 0;

        [JsonPropertyName("iat")]
        public long IssuedAtUnix { get; set; } = 0;

        public DistINTokenPayload()
        {
            this.SetIssuedAt(DateTime.UtcNow);
        }

        public void SetExpirationTime(DateTime value)
        {
            this.ExpirationTimeUnix = GetUnixTime(value);
        }
        public DateTime GetExpirationTime()
        {
            return GetTimeFromUnix(this.ExpirationTimeUnix);
        }

        public void SetNotBefore(DateTime value)
        {
            this.NotBeforeUnix = GetUnixTime(value);
        }
        public DateTime GetNotBefore()
        {
            return GetTimeFromUnix(this.NotBeforeUnix);
        }

        public void SetIssuedAt(DateTime value)
        {
            this.IssuedAtUnix = GetUnixTime(value);
        }
        public DateTime GetIssuedAt()
        {
            return GetTimeFromUnix(this.IssuedAtUnix);
        }

        public static DateTime GetTimeFromUnix(long unix)
        {
            return new DateTime(1970, 1, 1).AddSeconds(unix);
        }
        public static long GetUnixTime(DateTime time)
        {
            if (time == DateTime.MinValue)
            {
                return 0;
            }

            return Convert.ToInt64((time - new DateTime(1970, 1, 1)).TotalSeconds);
        }


        public string ToJsonString()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
            });
        }
        public override string ToString()
        {
            return CryptHelper.EncodeUrlBase64(Encoding.UTF8.GetBytes(this.ToJsonString()));
        }

        public static DistINTokenPayload FromString(string headerString)
        {
            byte[] data = CryptHelper.DecodeUrlBase64(headerString);
            string json = Encoding.UTF8.GetString(data);
            return JsonSerializer.Deserialize<DistINTokenPayload>(json, new JsonSerializerOptions()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
            })!;
        }

        public byte[] ToByteArray()
        {
            return Encoding.UTF8.GetBytes(this.ToJsonString());
        }
        public static DistINTokenPayload FromByteArray(byte[] headerData)
        {
            string json = Encoding.UTF8.GetString(headerData);
            return JsonSerializer.Deserialize<DistINTokenPayload>(json, new JsonSerializerOptions()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
            })!;
        }
    }

    public enum DistINTokenValidationResult
    {
        Success,
        Invalid_Signature,
        Invalid_Subject,
        Expired,
        Not_Yet_Valid
    }
}
