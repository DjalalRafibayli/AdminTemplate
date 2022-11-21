using API.JWT.Model;
using System.Security.Claims;
using System.Threading.Tasks;

namespace API.JWT.Interface
{
    public interface IJwtSerivce
    {
        Task<Tokens> Authenticate(JWTUsers jWTUsers);
        Tokens GenerateRefreshToken(string username);
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
        string GenerateRefreshTokenFirst();
    }
}
