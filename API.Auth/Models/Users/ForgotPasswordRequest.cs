using System.ComponentModel.DataAnnotations;

namespace WebApi.Models.Users
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}