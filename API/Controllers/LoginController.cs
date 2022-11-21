using API.JWT.Interface;
using API.JWT.Model;
using Application.Abstract.Users;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : Controller
    {
        private readonly IJwtSerivce _jWTService;
        private readonly IUserDal _userDal;
        public LoginController(IJwtSerivce jWTService, IUserDal userDal)
        {
            _jWTService = jWTService;
            _userDal = userDal;
        }
        [HttpPost]
        [Route("authenticate")]
        public async Task<IActionResult> Authenticate(JWTUsers usersdata)
        {
            JWTUsers user = new JWTUsers
            {
                username = usersdata.username,
                password = usersdata.password,
            };
            var token = await _jWTService.Authenticate(user);
            if (token == null)
            {
                return Unauthorized();
            }
            setTokenCookie(token.RefreshToken);

            return Ok(token);
        }
        [HttpPost]
        [Route("refresh")]
        public IActionResult Refresh(Tokens token)//,string username
        {
            try
            {
                var principal = _jWTService.GetPrincipalFromExpiredToken(token.Token);
                if (principal == null)
                {
                    return BadRequest("Invalid access token or refresh token");
                }
                var username = principal.Identity?.Name;

                //retrieve the saved refresh token from database
                var savedRefreshToken = _userDal.GetSavedRefreshTokens(username, token.RefreshToken);
                if (savedRefreshToken == null)
                {
                    return Unauthorized("Invalid attempt!");
                }
                if (savedRefreshToken.RefreshToken != token.RefreshToken || savedRefreshToken.RefreshTokenExpireTime <= DateTime.Now)
                {
                    return Unauthorized("Invalid attempt!");
                }

                var newJwtToken = _jWTService.GenerateRefreshToken(username);

                if (newJwtToken == null)
                {
                    return Unauthorized("Invalid attempt!");
                }

                _userDal.UpdateUserRefreshToken(username, newJwtToken.RefreshToken);
                
                return Ok(newJwtToken);
            }
            catch (Exception ex)
            {
                return Unauthorized("Invalid attempt!");
            }
        }


        //ancaq refresh token parametri gondermekle token almaq
        [HttpPost]
        [Route("refreshToken")]
        public IActionResult RefreshToken([FromForm] string refreshToken)//,string username
        {
            try
            {
                //retrieve the saved refresh token from database
                var savedRefreshToken = _userDal.GetSavedRefreshTokensWithRefresh(refreshToken);

                if (savedRefreshToken == null)
                {
                    return Unauthorized("Invalid attempt!");
                }
                if (savedRefreshToken.RefreshToken != refreshToken || savedRefreshToken.RefreshTokenExpireTime <= DateTime.Now)
                {
                    return Unauthorized("Invalid attempt!");
                }

                var newJwtToken = _jWTService.GenerateRefreshToken(savedRefreshToken.Username);

                if (newJwtToken == null)
                {
                    return Unauthorized("Invalid attempt!");
                }
                _userDal.UpdateUserRefreshToken(savedRefreshToken.Username, newJwtToken.RefreshToken);
                return Ok(newJwtToken);
            }
            catch (Exception ex)
            {
                return Unauthorized("Invalid attempt!");
            }
        }

        private void setTokenCookie(string token)
        {
            // append cookie with refresh token to the http response
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddHours(1)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }
    }
}
