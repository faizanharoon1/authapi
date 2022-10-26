using AutoMapper;
using BC = BCrypt.Net.BCrypt;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Models.Users;

namespace WebApi.Services
{
    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAddress);
        void RevokeToken(string token, string ipAddress);
        void Register(RegisterRequest model, string origin);
        void VerifyEmail(string token);
        void ForgotPassword(ForgotPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest model);
        void ResetPassword(ResetPasswordRequest model);
        IEnumerable<UserResponse> GetAll();
        UserResponse GetById(Guid id);
        UserResponse GetById(int id);
        UserResponse Create(CreateRequest model);
        UserResponse Update(int id, UpdateRequest model);
        void Delete(int id);
    }

    public class UserService : IUserService
    {
        private readonly DataContext _context;
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;
        private readonly IEmailService _emailService;

        public UserService(
            DataContext context,
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            IEmailService emailService)
        {
            _context = context;
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _emailService = emailService;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            var User = _context.Users.SingleOrDefault(x => x.Email == model.Username);
            if (User == null || !User.IsVerified )
                throw new AppException("User is unverified! Please check your email!");

            if (!BC.Verify(model.Password, User.PasswordHash))
                throw new AppException("Email or password is incorrect");

            // authentication successful so generate jwt and refresh tokens
            var jwtToken = generateJwtToken(User);
            var refreshToken = generateRefreshToken(ipAddress);
            User.RefreshTokens.Add(refreshToken);

            // remove old refresh tokens from User
            removeOldRefreshTokens(User);

            // save changes to db
            _context.Update(User);
            _context.SaveChanges();

            var response = _mapper.Map<AuthenticateResponse>(User);
            response.Access_token = jwtToken;
            response.RefreshToken = refreshToken.Token;
            return response;
        }

        public AuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var (refreshToken, User) = getRefreshToken(token);

            // replace old refresh token with a new one and save
            var newRefreshToken = generateRefreshToken(ipAddress);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            User.RefreshTokens.Add(newRefreshToken);

            removeOldRefreshTokens(User);

            _context.Update(User);
            _context.SaveChanges();

            // generate new jwt
            var jwtToken = generateJwtToken(User);

            var response = _mapper.Map<AuthenticateResponse>(User);
            response.Access_token = jwtToken;
            response.RefreshToken = newRefreshToken.Token;
            return response;
        }

        public void RevokeToken(string token, string ipAddress)
        {
            var (refreshToken, User) = getRefreshToken(token);

            // revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            _context.Update(User);
            _context.SaveChanges();
        }

        public void Register(RegisterRequest model, string origin)
        {
            // validate
            if (_context.Users.Any(x => x.Email == model.Email))
            {
                // send already registered error in email to prevent User enumeration
                sendAlreadyRegisteredEmail(model.Email, origin);
                return;
            }

            // map model to new User object
            var User = _mapper.Map<User>(model);

            // first registered User is an admin
            var isFirstUser = _context.Users.Count() == 0;
            User.Role = isFirstUser ? Role.Admin : Role.User;
            User.Created = DateTime.UtcNow;
            User.VerificationToken = randomTokenString();

            // hash password
            User.PasswordHash = BC.HashPassword(model.Password);

            // generate GUID
            User.UserGuid = Guid.NewGuid();

            // save User
            _context.Users.Add(User);
            _context.SaveChanges();

            // send email
            sendVerificationEmail(User, origin);
        }

        public void VerifyEmail(string token)
        {
            var User = _context.Users.SingleOrDefault(x => x.VerificationToken == token);

            if (User == null) throw new AppException("Verification failed");

            User.Verified = DateTime.UtcNow;
            User.VerificationToken = null;

            _context.Users.Update(User);
            _context.SaveChanges();
        }

        public void ForgotPassword(ForgotPasswordRequest model, string origin)
        {
            var User = _context.Users.SingleOrDefault(x => x.Email == model.Email);

            // always return ok response to prevent email enumeration
            if (User == null) return;

            // create reset token that expires after 1 day
            User.ResetToken = randomTokenString();
            User.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

            _context.Users.Update(User);
            _context.SaveChanges();

            // send email
            sendPasswordResetEmail(User, origin);
        }

        public void ValidateResetToken(ValidateResetTokenRequest model)
        {
            var User = _context.Users.SingleOrDefault(x =>
                x.ResetToken == model.Token &&
                x.ResetTokenExpires > DateTime.UtcNow);

            if (User == null)
                throw new AppException("Invalid token");
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            var User = _context.Users.SingleOrDefault(x =>
                x.ResetToken == model.Token &&
                x.ResetTokenExpires > DateTime.UtcNow);

            if (User == null)
                throw new AppException("Invalid token");

            // update password and remove reset token
            User.PasswordHash = BC.HashPassword(model.Password);
            User.PasswordReset = DateTime.UtcNow;
            User.ResetToken = null;
            User.ResetTokenExpires = null;

            _context.Users.Update(User);
            _context.SaveChanges();
        }

        public IEnumerable<UserResponse> GetAll()
        {
            var Users = _context.Users;
            return _mapper.Map<IList<UserResponse>>(Users);
        }

        public UserResponse GetById(int id)
        {
            var User = getUser(id);
            return _mapper.Map<UserResponse>(User);
        }
        public UserResponse GetById(Guid id)
        {
            var User = getUser(id);
            return _mapper.Map<UserResponse>(User);
        }
        public UserResponse Create(CreateRequest model)
        {
            // validate
            if (_context.Users.Any(x => x.Email == model.Email))
                throw new AppException($"Email '{model.Email}' is already registered");

            // map model to new User object
            var User = _mapper.Map<User>(model);
            User.Created = DateTime.UtcNow;
            User.Verified = DateTime.UtcNow;

            // hash password
            User.PasswordHash = BC.HashPassword(model.Password);

            // save User
            _context.Users.Add(User);
            _context.SaveChanges();

            return _mapper.Map<UserResponse>(User);
        }

        public UserResponse Update(int id, UpdateRequest model)
        {
            var User = getUser(id);

            // validate
            if (User.Email != model.Email && _context.Users.Any(x => x.Email == model.Email))
                throw new AppException($"Email '{model.Email}' is already taken");

            // hash password if it was entered
            if (!string.IsNullOrEmpty(model.Password))
                User.PasswordHash = BC.HashPassword(model.Password);

            // copy model to User and save
            _mapper.Map(model, User);
            User.Updated = DateTime.UtcNow;
            _context.Users.Update(User);
            _context.SaveChanges();

            return _mapper.Map<UserResponse>(User);
        }

        public void Delete(int id)
        {
            var User = getUser(id);
            _context.Users.Remove(User);
            _context.SaveChanges();
        }

        // helper methods

        private User getUser(int id)
        {
            var User = _context.Users.Find(id);
            if (User == null) throw new KeyNotFoundException("User not found");
            return User;
        }
        private User getUser(Guid id)
        {
            var User = _context.Users.FirstOrDefault(x=>x.UserGuid.Equals(id));
            if (User == null) throw new KeyNotFoundException("User not found");
            return User;
        }
        private (RefreshToken, User) getRefreshToken(string token)
        {
            var User = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (User == null) throw new AppException("Invalid token");
            var refreshToken = User.RefreshTokens.Single(x => x.Token == token);
            if (!refreshToken.IsActive) throw new AppException("Invalid token");
            return (refreshToken, User);
        }

        private string generateJwtToken(User User)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", User.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken generateRefreshToken(string ipAddress)
        {
            return new RefreshToken
            {
                Token = randomTokenString(),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }

        private void removeOldRefreshTokens(User User)
        {
            User.RefreshTokens.RemoveAll(x => 
                !x.IsActive && 
                x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
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
