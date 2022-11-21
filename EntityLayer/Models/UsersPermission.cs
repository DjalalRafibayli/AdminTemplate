using System;
using System.Collections.Generic;

#nullable disable

namespace EntityLayer.Models
{
    public partial class UsersPermission
    {
        public int Id { get; set; }
        public int? UserId { get; set; }
        public string Perm { get; set; }
        public byte? Active { get; set; }

        public virtual User User { get; set; }
    }
}
