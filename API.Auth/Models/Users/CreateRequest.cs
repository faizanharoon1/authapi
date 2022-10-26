using System.ComponentModel.DataAnnotations;
using WebApi.Entities;

namespace WebApi.Models.Users
{
    public class CreateRequest
    {

        public string Title { get; set; }

    
        public string FirstName { get; set; }

  
        public string LastName { get; set; }

     
        [EnumDataType(typeof(Role))]
        public string Role { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }

        [Required]
        [Compare("Password")]
        public string ConfirmPassword { get; set; }
    }
}