using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace DistIN.Application.Controllers
{
    public class OpenIDController : Controller
    {
        private static ConcurrentDictionary<string, string> _authSessions = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, bool> _revokedTokens = new ConcurrentDictionary<string, bool>();

        [Route(".well-known/openid-configuration")]
        public IActionResult Config()
        {
            return Json(new
            {
                issuer = $"https://{AppConfig.Current.ServiceDomain}",
                authorization_endpoint = $"https://{AppConfig.Current.ServiceDomain}/openid/authorize",
                token_endpoint = $"https://{AppConfig.Current.ServiceDomain}/openid/token",
                userinfo_endpoint = $"https://{AppConfig.Current.ServiceDomain}/openid/userinfo",
                jwks_uri = $"https://{AppConfig.Current.ServiceDomain}/.well-known/jwks.json",
                end_session_endpoint = $"https://{AppConfig.Current.ServiceDomain}/openid/logout",
                response_types_supported = new string[] { "code", "id_token", "token id_token" },
                subject_types_supported = new string[] { "public", "pairwise" },
                id_token_signing_alg_values_supported = new string[] { "RS512" },
                scopes_supported = new string[] { "openid", "profile", "email" },
                token_endpoint_auth_methods_supported = new string[] { "client_secret_basic", "client_secret_post" },
                grant_types_supported = new string[] { "authorization_code", "implicit", "refresh_token" },
                claims_supported = new string[] { "sub", "name", "email", "preferred_username" },
                code_challenge_methods_supported = new string[] { "plain", "S256" },
            });
        }

        [Route(".well-known/jwks.json")]
        public IActionResult Jwks()
        {
            using (var rsa = AppConfig.Current.OpenID_RSA_KeyPair.GetRSA())
            {
                var parameters = rsa.ExportParameters(false);

                var key = new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = $"{AppConfig.Current.ServiceDomain}",
                    alg = "RS512",
                    n = Convert.ToBase64String(parameters.Modulus!),
                    e = Convert.ToBase64String(parameters.Exponent!)
                };

                var jwks = new { keys = new[] { key } };

                return Json(jwks);
            }
        }

        public IActionResult Authorize(string response_type, string client_id, string redirect_uri, string scope, string state)
        {
            if (Database.OpenIDClients.Find(client_id) == null)
            {
                return BadRequest(new { error = "invalid_client" });
            }

            this.HttpContext.Session.SetString("redirect_uri", redirect_uri);
            this.HttpContext.Session.SetString("state", state);
            this.HttpContext.Session.SetString("scope", scope);

            if (this.HttpContext.IsLoggedIn())
                return ConfirmAuthorization();
            else
                return View();
        }
        public IActionResult ConfirmAuthorization()
        {
            string identity = this.HttpContext.GetIdentity();

            string redirect_uri = this.HttpContext.Session.GetString("redirect_uri")!;
            string state = this.HttpContext.Session.GetString("state")!;

            string authCode = IDGenerator.GenerateGUID();

            _authSessions[authCode] = identity;

            if (redirect_uri.Contains('?'))
                return Redirect($"{redirect_uri}&code={authCode}&state={state}");
            else
                return Redirect($"{redirect_uri}?code={authCode}&state={state}");
        }

        public IActionResult Token([FromForm] string grant_type, [FromForm] string code,
            [FromForm] string client_id, [FromForm] string client_secret, [FromForm] string redirect_uri)
        {
            if (grant_type != "authorization_code" || !_authSessions.ContainsKey(code))
            {
                return BadRequest(new { error = "invalid_grant" });
            }

            OpenIDClient? client = Database.OpenIDClients.Find(client_id);
            if (client == null || client_secret != client.Secret)
            {
                return BadRequest(new { error = "invalid_client" });
            }

            //string identity = _authSessions[code];
            string identity = _authSessions[code];
            _authSessions.TryRemove(code, out _);

            var idToken = generateJwtToken(identity, true, client_id);
            var accessToken = generateJwtToken(identity, false, client_id);

            return Json(new
            {
                access_token = accessToken,
                id_token = idToken,
                token_type = "Bearer",
                expires_in = 3600
            });
        }

        private string generateJwtToken(string identity, bool isIdToken, string client_id)
        {
            var securityKey = new RsaSecurityKey(AppConfig.Current.OpenID_RSA_KeyPair.GetRSA());
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha512);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, identity),
                new Claim(JwtRegisteredClaimNames.UniqueName, identity),
                new Claim(JwtRegisteredClaimNames.Iss, $"https://{AppConfig.Current.ServiceDomain}"),
                new Claim(JwtRegisteredClaimNames.Aud, client_id),
                new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(60).ToUnixTimeSeconds().ToString())
            };

            if (isIdToken)
            {
                // TODO: claims.Add(new Claim(JwtRegisteredClaimNames.Email, "admin@example.com"));
            }

            var token = new JwtSecurityToken(
                issuer: $"https://{AppConfig.Current.ServiceDomain}",
                audience: client_id,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: credentials
            );
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public IActionResult UserInfo()
        {
            // 1️⃣ Authorization Header auslesen
            var authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return Unauthorized(new { error = "missing_or_invalid_token" });
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();

            // 2️⃣ JWT validieren und Claims extrahieren
            var claimsPrincipal = validateToken(token);
            if (claimsPrincipal == null)
            {
                return Unauthorized(new { error = "invalid_token" });
            }

            // 3️⃣ Benutzerinformationen zurückgeben
            var userInfo = new
            {
                sub = claimsPrincipal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value,
                name = claimsPrincipal.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value,
                email = claimsPrincipal.FindFirst(JwtRegisteredClaimNames.Email)?.Value
            };

            return Json(userInfo);
        }

        private ClaimsPrincipal? validateToken(string token)
        {
            try
            {
                if (_revokedTokens.ContainsKey(token))
                    return null;

                var tokenHandler = new JwtSecurityTokenHandler();
                var rsaKey = AppConfig.Current.OpenID_RSA_KeyPair.GetRSA();

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = $"https://{AppConfig.Current.ServiceDomain}",
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    IssuerSigningKey = new RsaSecurityKey(rsaKey),
                    ValidateIssuerSigningKey = true
                };

                validationParameters.ValidAudiences = Database.OpenIDClients.All().Select(a => a.ID);

                return tokenHandler.ValidateToken(token, validationParameters, out _);
            }
            catch
            {
                return null;
            }
        }

        public IActionResult Logout(string post_logout_redirect_uri)
        {
            // 1️⃣ Benutzer abmelden (Session & Cookies löschen)
            HttpContext.Logout();

            // 2️⃣ Umleitung zur angegebenen Logout-Redirect-URL
            if (!string.IsNullOrEmpty(post_logout_redirect_uri))
            {
                return Redirect(post_logout_redirect_uri);
            }

            return Ok(new { message = "Logged out" });
        }

        public IActionResult Revoke(
            [FromForm] string token,
            [FromForm] string token_type_hint,
            [FromForm] string client_id,
            [FromForm] string client_secret)
        {
            OpenIDClient? client = Database.OpenIDClients.Find(client_id);
            if (client == null || client_secret != client.Secret)
            {
                return BadRequest(new { error = "invalid_client" });
            }

            _revokedTokens[token] = true;

            return Ok();
        }
    }

}
