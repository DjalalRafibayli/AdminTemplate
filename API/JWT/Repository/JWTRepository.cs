using API.JWT.Interface;
using API.JWT.Model;
using Application.Abstract.Users;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace API.JWT.Repository
{
    public class JWTRepository : IJwtSerivce
    {
        private readonly IConfiguration _configuration;
        private readonly IUserDal _userDal;

        public JWTRepository(IConfiguration configuration, IUserDal userDal)
        {
            _configuration = configuration;
            _userDal = userDal;
        }

        public async Task<Tokens> Authenticate(JWTUsers jWTUsers)
        {
            if (!_userDal.CheckUserExist(jWTUsers.username, jWTUsers.password))
            {
                return null;
            }
            var userPerm = await _userDal.UserWithPerm(jWTUsers.username, jWTUsers.password);
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, jWTUsers.username)
            };
            var roles = userPerm.usersPermissions;
            
            claims.AddRange(roles.Select(role => new Claim(ClaimsIdentity.DefaultRoleClaimType, role.Perm)));
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(_configuration["JWT:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature),
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);


            var refreshToken = GenerateRefreshTokenFirst();
            _userDal.UpdateUserRefreshToken(jWTUsers.username, refreshToken);


            Tokens tokens = new Tokens()
            {
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken
            };

            return tokens;
        }

        public Tokens GenerateRefreshToken(string username)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                  {
                 new Claim(ClaimTypes.Name, username)
                  }),
                    Expires = DateTime.Now.AddMinutes(30),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var refreshToken = GenerateRefreshTokenFirst();
                return new Tokens { Token = tokenHandler.WriteToken(token), RefreshToken = refreshToken };
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public string GenerateRefreshTokenFirst()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            try
            {
                var Key = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false, // on production make it true
                    ValidateAudience = false, // on production make it true
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _configuration["JWT:Issuer"],
                    ValidAudience = _configuration["JWT:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Key),
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
                JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;
                if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    throw new SecurityTokenException("Invalid token");
                }

                return principal;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
