using Application.Dtos.Users;
using EntityLayer.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Abstract.Users
{
    public interface IUserDal
    {
        bool CheckUserExist(string username, string password);
        Task<UserWithPermisson> UserWithPerm(string username, string password);
        User GetSavedRefreshTokens(string username, string refreshtoken);
        User GetSavedRefreshTokensWithRefresh(string refreshToken);
        void UpdateUserRefreshToken(string username, string refreshToken);
    }
}
