using System.ComponentModel.DataAnnotations;

namespace ADMIN.Models.CustomModels.Login
{
    public class LoginModel
    {
        [Required]
        public string username { get; set; }
        [Required]
        public string password { get; set; }
    }
}
