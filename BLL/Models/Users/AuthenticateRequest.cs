using System.ComponentModel.DataAnnotations;

namespace BLL.Models.Users
{
    public class AuthenticateRequest
    {
        [EmailAddress]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
