using AutoMapper;
using BLL.Helpers;
using BLL.Models.Users;
using DAL;
using DAL.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BC = BCrypt.Net.BCrypt;

namespace BLL.Services
{
    public interface IUserService
    {
        Task<AuthenticateResponse> Authenticate(AuthenticateRequest model, string ipAddress);
        Task<AuthenticateResponse> RefreshToken(string token, string ipAddress);
        Task<RefreshToken> GetRefreshToken(string token);
        Task RevokeToken(string token, string ipAddress);
        Task Register(RegisterRequest model, string origin);
        Task VerifyEmail(VerifyEmailRequest model);
        void ForgotPassword(ForgotPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest model);
        void ResetPassword(ResetPasswordRequest model);
        IEnumerable<UserResponse> GetAll();
        Task<UserResponse> GetById(Guid id);
        Task<UserResponse> GetById(int id);
        UserResponse Create(CreateRequest model);
        UserResponse Update(int id, UpdateRequest model);
        void Delete(int id);
    }

    public class UserService : IUserService
    {
        private readonly IDbContext _context;
        private readonly IMapper _mapper;
        private readonly IOptions<AppSettings> _appSettings;
        private readonly IEmailService _emailService;

        public UserService(
            IDbContext context,
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            IEmailService emailService)
        {
            _context = context;
            _mapper = mapper;
            _appSettings = appSettings;
            _emailService = emailService;
        }

        public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest model, string ipAddress)
        {
            User existingUser = await GetUserByEmail(model.Username);
            if (existingUser == null || !existingUser.IsVerified)
                throw new AppException("User is unverified! Please check your email!");

            if (!BC.Verify(model.Password, existingUser.PasswordHash))
                throw new AppException("Email or password is incorrect");

            // authentication successful so generate jwt and refresh tokens
            var jwtToken = generateJwtToken(existingUser);
            // save changes to db
            await _context.UpdateAsync(existingUser);


            RefreshToken refreshToken = await GetRefreshTokensByUserId(existingUser.Id);
            if (refreshToken == null)
            {
                refreshToken = await generateRefreshToken(ipAddress, existingUser.Id);
            }
            else if(refreshToken.IsExpired)
                refreshToken = await generateRefreshToken(ipAddress, existingUser.Id);


            var response = _mapper.Map<AuthenticateResponse>(existingUser);
            response.Access_token = jwtToken;
            response.RefreshToken = refreshToken.Token;
            return response;
        }

        //private async Task<RefreshToken> SaveOrUpdateRefreshToken(string ipAddress, User existingUser)
        //{
        //    var refreshToken = generateRefreshToken(ipAddress);
        //    if (existingUser.RefreshTokens == null)
        //        existingUser.RefreshTokens = new List<RefreshToken>();

        //    refreshToken.UserId = existingUser.Id;
        //    existingUser.RefreshTokens.Add(refreshToken);
        //    // remove old refresh tokens from User
        //    removeOldRefreshTokens(existingUser.RefreshTokens);
        //    await SaveRefreshTokens(existingUser.RefreshTokens);
        //    return refreshToken;
        //}


        public async Task<AuthenticateResponse> RefreshToken(string token, string ipAddress)
        {
            RefreshToken? newRefreshToken = null;
            var refreshToken = await GetRefreshToken(token);
            if (refreshToken == null) throw new SecurityTokenExpiredException("Token sent from client does not exist!");

            var user = await GetUserById(refreshToken.UserId);
            if (user == null) throw new AppException("Invalid token");


            if (refreshToken.IsExpired)
            {
                // replace old refresh token with a new one and save
                newRefreshToken = await generateRefreshToken(ipAddress, user.Id);

                refreshToken.UserId = user.Id;
                refreshToken.Revoked = DateTime.UtcNow;
                refreshToken.RevokedByIp = ipAddress;
                refreshToken.ReplacedByToken = newRefreshToken.Token;
                await _context.UpdateAsync(refreshToken);

                refreshToken = newRefreshToken;
            }

            // generate new jwt
            var jwtToken = generateJwtToken(user);
            var response = _mapper.Map<AuthenticateResponse>(user);
            response.Access_token = jwtToken;
            response.RefreshToken = refreshToken.Token;
            return response;

        }

        public async Task RevokeToken(string token, string ipAddress)
        {
            var refreshToken = await GetRefreshToken(token);

            // revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            await _context.UpdateAsync(refreshToken);
        }

        public async Task Register(RegisterRequest model, string origin)
        {
            User existingUser = await GetUserByEmail(model.Email);

            // validate
            if (existingUser?.Email == model.Email)
            {
                // send already registered error in email to prevent User enumeration
                sendAlreadyRegisteredEmail(model.Email, origin);
                return;
            }

            // map model to new User object
            var User = _mapper.Map<User>(model);

            User.Role = Role.User;
            User.Created = DateTime.UtcNow;
            User.VerificationToken = randomTokenString();

            // hash password
            User.PasswordHash = BC.HashPassword(model.Password);

            // generate GUID
            User.UserGuid = Guid.NewGuid();

            // save User
            await _context.InsertAsync(User);

            // send email
            sendVerificationEmail(User, origin);


        }

        public async Task VerifyEmail(VerifyEmailRequest model)
        {
            var User = await _context.QueryFirstOrDefaultAsync<User>("SELECT * FROM ef.users WHERE UserGuid=@UserGuid;", new { model.UserGuid });

            if (User == null || User.VerificationToken != model.Token) throw new AppException("Verification failed");

            User.Verified = DateTime.UtcNow;
            User.VerificationToken = null;

            await _context.UpdateAsync(User);
        }

        public void ForgotPassword(ForgotPasswordRequest model, string origin)
        {
            //var User = _context.Users.SingleOrDefault(x => x.Email == model.Email);

            //// always return ok response to prevent email enumeration
            //if (User == null) return;

            //// create reset token that expires after 1 day
            //User.ResetToken = randomTokenString();
            //User.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

            //_context.Users.Update(User);
            //_context.SaveChanges();

            //// send email
            //sendPasswordResetEmail(User, origin);
        }

        public void ValidateResetToken(ValidateResetTokenRequest model)
        {
            //var User = _context.Users.SingleOrDefault(x =>
            //    x.ResetToken == model.Token &&
            //    x.ResetTokenExpires > DateTime.UtcNow);

            //if (User == null)
            //    throw new AppException("Invalid token");
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            //var User = _context.Users.SingleOrDefault(x =>
            //    x.ResetToken == model.Token &&
            //    x.ResetTokenExpires > DateTime.UtcNow);

            //if (User == null)
            //    throw new AppException("Invalid token");

            //// update password and remove reset token
            //User.PasswordHash = BC.HashPassword(model.Password);
            //User.PasswordReset = DateTime.UtcNow;
            //User.ResetToken = null;
            //User.ResetTokenExpires = null;

            //_context.Users.Update(User);
            //_context.SaveChanges();
        }

        public IEnumerable<UserResponse> GetAll()
        {
            //var Users = _context.Users;
            //return _mapper.Map<IList<UserResponse>>(Users);
            return null;
        }
        async Task<User> GetUserByEmail(string email)
        {
            var User = await _context.QueryFirstOrDefaultAsync<User>("SELECT * FROM ef.users WHERE Email=@email;", new { email });
            if (User == null) throw new KeyNotFoundException("User not found");

            return User;
        }
        public async Task<User> GetUserById(int id)
        {
            var User = await getUser(id);
            return User;
        }
        public async Task<UserResponse> GetById(int id)
        {
            var User = await getUser(id);
            return _mapper.Map<UserResponse>(User);
        }
        public async Task<UserResponse> GetById(Guid id)
        {
            var User = await getUser(id);
            return _mapper.Map<UserResponse>(User);
        }
        public UserResponse Create(CreateRequest model)
        {
            // validate
            //if (_context.Users.Any(x => x.Email == model.Email))
            //    throw new AppException($"Email '{model.Email}' is already registered");

            //// map model to new User object
            //var User = _mapper.Map<User>(model);
            //User.Created = DateTime.UtcNow;
            //User.Verified = DateTime.UtcNow;

            //// hash password
            //User.PasswordHash = BC.HashPassword(model.Password);

            //// save User
            //_context.Users.Add(User);
            //_context.SaveChanges();

            //return _mapper.Map<UserResponse>(User);
            return null;
        }

        public UserResponse Update(int id, UpdateRequest model)
        {
            //var User = getUser(id);

            //// validate
            //if (User.Email != model.Email && _context.Users.Any(x => x.Email == model.Email))
            //    throw new AppException($"Email '{model.Email}' is already taken");

            //// hash password if it was entered
            //if (!string.IsNullOrEmpty(model.Password))
            //    User.PasswordHash = BC.HashPassword(model.Password);

            //// copy model to User and save
            //_mapper.Map(model, User);
            //User.Updated = DateTime.UtcNow;
            //_context.Users.Update(User);
            //_context.SaveChanges();

            //return _mapper.Map<UserResponse>(User);
            return null;
        }

        public void Delete(int id)
        {
            //var User = getUser(id);
            //_context.Users.Remove(User);
            //_context.SaveChanges();
        }

        // helper methods

        private async Task<User> getUser(Guid id)
        {
            var User = await _context.QueryFirstOrDefaultAsync<User>("SELECT * FROM ef.users WHERE UserGuid=@UserGuid;", new { @UserGuid = id });

            if (User == null) throw new KeyNotFoundException("User not found");

            return User;

        }
        private async Task<User> getUser(int id)
        {
            var User = await _context.QueryFirstOrDefaultAsync<User>("SELECT * FROM ef.users WHERE Id=@id;", new { id });

            if (User == null) throw new KeyNotFoundException("User not found");

            return User;

        }

        private async Task<RefreshToken> GetRefreshTokensByUserId(int Id)
        {
            return await _context.QueryFirstOrDefaultAsync<RefreshToken>("SELECT * FROM ef.refreshtokens WHERE UserId=@Id and revoked is  null;", new { Id });
        }
        private async Task<RefreshToken> GetRefreshTokensById(int Id)
        {
            return await _context.QueryFirstOrDefaultAsync<RefreshToken>("SELECT * FROM ef.refreshtokens WHERE Id=@Id and revoked is  null;", new { Id });
        }
        public async Task<RefreshToken> GetRefreshToken(string token)
        {
            var refreshToken = await _context.QueryFirstOrDefaultAsync<RefreshToken>("SELECT * FROM ef.refreshtokens WHERE Token=@token;", new { token });

            if (!refreshToken.IsActive) throw new AppException("Invalid token");
            return refreshToken;
        }

        private string generateJwtToken(User User)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Value.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", User.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private async Task<RefreshToken> generateRefreshToken(string ipAddress, int UserId)
        {
            var newToken = new RefreshToken
            {
                UserId = UserId,
                Token = randomTokenString(),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };

            int res = await _context.InsertAsync(newToken);
            if (res <= 0)
                throw new InvalidDataException("generateRefreshToken failed");

            return newToken;
        }

        private string randomTokenString()
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            // convert random bytes to hex string
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }

        private void sendVerificationEmail(User User, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var verifyUrl = $"{origin}/User/verify-email?token={User.VerificationToken}";
                message = $@"<p>Please click the below link to verify your email address:</p>
                             <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to verify your email address with the <code>/Users/verify-email</code> api route:</p>
                             <p><code>{User.VerificationToken}</code></p>";
            }

            _emailService.Send(
                to: User.Email,
                subject: "Sign-up Verification API - Verify Email",
                html: $@"<h4>Verify Email</h4>
                         <p>Thanks for registering!</p>
                         {message}"
            );
        }

        private void sendAlreadyRegisteredEmail(string email, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
                message = $@"<p>If you don't know your password please visit the <a href=""{origin}/User/forgot-password"">forgot password</a> page.</p>";
            else
                message = "<p>If you don't know your password you can reset it via the <code>/Users/forgot-password</code> api route.</p>";

            _emailService.Send(
                to: email,
                subject: "Sign-up Verification API - Email Already Registered",
                html: $@"<h4>Email Already Registered</h4>
                         <p>Your email <strong>{email}</strong> is already registered.</p>
                         {message}"
            );
        }

        private void sendPasswordResetEmail(User User, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/User/reset-password?token={User.ResetToken}";
                message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                             <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/Users/reset-password</code> api route:</p>
                             <p><code>{User.ResetToken}</code></p>";
            }

            _emailService.Send(
                to: User.Email,
                subject: "Sign-up Verification API - Reset Password",
                html: $@"<h4>Reset Password Email</h4>
                         {message}"
            );
        }
    }
}
