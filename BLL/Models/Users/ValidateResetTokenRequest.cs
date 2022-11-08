using System.ComponentModel.DataAnnotations;

namespace BLL.Models.Users
{
    public class ValidateResetTokenRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
