using System.ComponentModel.DataAnnotations;

namespace BLL.Models.Users
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
