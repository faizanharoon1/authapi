using DAL;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using DAL.Entities;

namespace API.Auth.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;

        public JwtMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
        {
            _next = next;
            _appSettings = appSettings.Value;
        }

        public async Task Invoke(HttpContext context, IDbContext dataContext)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
                await attachUserToContext(context, dataContext, token);
            else
            {
                if(context.Request.Cookies["refreshToken"]!=null)
                {

                }
            }
            await _next(context);
        }

        private async Task attachUserToContext(HttpContext context, IDbContext dataContext, string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var Id = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                // attach User to context on successful jwt validation
                context.Items["User"] = await dataContext.QueryFirstOrDefaultAsync<User>("SELECT * FROM ef.users where Id=@Id;", new { Id });
            }
            catch
            {
                throw;
                // do nothing if jwt validation fails
                // User is not attached to context so request won't have access to secure routes
            }
        }
    }
}
