using System.ComponentModel.DataAnnotations;

namespace WebApi.Models.Users
{
    public class ValidateResetTokenRequest
    {
        [Required]
        public string Token { get; set; }
    }
}