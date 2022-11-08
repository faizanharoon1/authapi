using System.ComponentModel.DataAnnotations;

namespace BLL.Models.Users
{
    public class VerifyEmailRequest
    {
        [Required]
        public string Token { get; set; }
        [Required]
        public string UserGuid { get; set; }
    }
}
