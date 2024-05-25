using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace POC_JWT.Service
{
    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime ExpiryDate { get; set; }
    }

    public interface ITokenService
    {
        string GenerateToken(string username);
        RefreshToken GenerateRefreshToken();
        void SaveRefreshToken(string username, RefreshToken refreshToken);
        RefreshToken GetRefreshToken(string username);
        void RemoveRefreshToken(string username);
    }

    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;
        
        // this disctonry should be in database or global dictonary.
        private readonly IDictionary<string, RefreshToken> _refreshTokens = new Dictionary<string, RefreshToken>();

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(string username)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = Encoding.ASCII.GetBytes(jwtSettings["Key"]);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddMinutes(double.Parse(jwtSettings["ExpiryMinutes"])),
                Issuer = jwtSettings["Issuer"],
                Audience = jwtSettings["Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiryDate = DateTime.UtcNow.AddDays(double.Parse(_configuration["Jwt:RefreshTokenExpiryDays"]))
            };

            return refreshToken;
        }

        public void SaveRefreshToken(string username, RefreshToken refreshToken)
        {
            _refreshTokens[username] = refreshToken;
        }

        public RefreshToken GetRefreshToken(string username)
        {
            return _refreshTokens.ContainsKey(username) ? _refreshTokens[username] : null;
        }

        public void RemoveRefreshToken(string username)
        {
            _refreshTokens.Remove(username);
        }
    }
}
