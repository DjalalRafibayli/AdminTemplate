using EntityLayer.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace Application.Dtos.Users
{
    public class UserWithPermisson
    {
        public int userId { get; set; }
        public string userName { get; set; }
        public List<UsersPermission> usersPermissions { get; set; }

    }
}
