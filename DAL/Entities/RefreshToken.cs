using System.ComponentModel.DataAnnotations;
using DAL;
using DAL.Entities;
using Dapper.Contrib.Extensions;

namespace DAL.Entities
{

    public class RefreshToken
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        [Computed]
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public DateTime Created { get; set; }
        public string CreatedByIp { get; set; }
        public DateTime? Revoked { get; set; }
        public string RevokedByIp { get; set; }
        public string ReplacedByToken { get; set; }
        [Computed]
        public bool IsActive => Revoked == null && !IsExpired;
    }
}
