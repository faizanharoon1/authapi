using System;
using System.Text.Json.Serialization;

namespace WebApi.Models.Users
{
    public class AuthenticateResponse
    {
        public Guid UserGuid { get; set; }
        [JsonIgnore]
        public string Title { get; set; }
        [JsonIgnore]
        public string FirstName { get; set; }
        [JsonIgnore]
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
        [JsonIgnore]
        public DateTime Created { get; set; }
        [JsonIgnore]
        public DateTime? Updated { get; set; }
        public bool IsVerified { get; set; }
        public string Access_token { get; set; }

        [JsonIgnore] // refresh token is returned in http only cookie
        public string RefreshToken { get; set; }
    }
}