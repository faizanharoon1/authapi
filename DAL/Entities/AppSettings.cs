using DAL;
namespace DAL.Entities
{
    public class AppSettings
    {
        public string Secret { get; set; }
        public string Salt { get; set; }
        // refresh token time to live (in days), inactive tokens are
        // automatically deleted from the database after this time
        public int RefreshTokenTTL { get; set; }

        public string EmailFrom { get; set; }
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpUser { get; set; }
        public string SmtpPass { get; set; }
    }

    public class ConnectionStrings
    {
        public string AuthConnectionString { get; set; }
    }
}
