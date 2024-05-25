using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using POC_JWT.Service;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace POC_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        private readonly IConfiguration _configuration;

        public AuthController(ITokenService tokenService, IConfiguration configuration)
        {
            _tokenService = tokenService;
            _configuration = configuration;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel login)
        {
            if (login.Username == "test" && login.Password == "password") // Dummy check for POC
            {
                var token = _tokenService.GenerateToken(login.Username);
                var refreshToken = _tokenService.GenerateRefreshToken();
                _tokenService.SaveRefreshToken(login.Username, refreshToken);
                return Ok(new { Token = token, RefreshToken = refreshToken.Token });
            }

            return Unauthorized();
        }

        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            var principal = GetPrincipalFromExpiredToken(request.Token);
            if (principal == null)
            {
                return BadRequest("Invalid token.");
            }

            var username = principal.Identity.Name;
            var savedRefreshToken = _tokenService.GetRefreshToken(username);

            if (savedRefreshToken == null || savedRefreshToken.Token != request.RefreshToken || savedRefreshToken.ExpiryDate <= DateTime.UtcNow)
            {
                return Unauthorized("Invalid refresh token.");
            }

            var newJwtToken = _tokenService.GenerateToken(username);
            var newRefreshToken = _tokenService.GenerateRefreshToken();
            _tokenService.SaveRefreshToken(username, newRefreshToken);

            return Ok(new { Token = newJwtToken, RefreshToken = newRefreshToken.Token });
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // Ignore expiration for now
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
    }

    public class RefreshRequest
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}