using Application.Abstract.Users;
using Application.Dtos.Users;
using EntityLayer.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Repositories.Users
{
    public class UserRepo : IUserDal
    {
        private readonly NTS_AdminContext _context;

        public UserRepo(NTS_AdminContext context)
        {
            _context = context;
        }

        public bool CheckUserExist(string username, string password)
        {
            return _context.Users.Any(x => x.Username == username && x.Password == password);
        }

        public async Task<UserWithPermisson> UserWithPerm(string username, string password)
        {
            var userwithPerm = await _context.Users.Include(x => x.UsersPermissions).FirstOrDefaultAsync(x => x.Username == username && x.Password == password);
            return new UserWithPermisson
            {
                userId = userwithPerm.Id,
                userName = userwithPerm.Username,
                usersPermissions = userwithPerm.UsersPermissions.Select(p => new UsersPermission
                {
                    Id = p.Id,
                    Active = p.Active,
                    Perm = p.Perm
                }).ToList()
            };
        }

        public User GetSavedRefreshTokens(string username, string refreshtoken)
        {
            return _context.Users.FirstOrDefault(x => x.Username == username && x.RefreshToken == refreshtoken && x.Active == 2);
        }

        public User GetSavedRefreshTokensWithRefresh(string refreshToken)
        {
            return _context.Users.FirstOrDefault(x => x.RefreshToken == refreshToken && x.Active == 2);
        }

        public void UpdateUserRefreshToken(string username, string refreshToken)
        {
            var user = _context.Users.FirstOrDefault(x => x.Username == username);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpireTime = DateTime.Now.AddMinutes(30);
            _context.Users.Update(user);

            _context.SaveChanges();
        }
    }
}
