using System;
using System.Collections.Generic;

#nullable disable

namespace EntityLayer.Models
{
    public partial class User
    {
        public User()
        {
            UsersPermissions = new HashSet<UsersPermission>();
        }

        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Name { get; set; }
        public string Firstname { get; set; }
        public string RefreshToken { get; set; }
        public DateTime? RefreshTokenExpireTime { get; set; }
        public byte? Active { get; set; }

        public virtual ICollection<UsersPermission> UsersPermissions { get; set; }
    }
}
