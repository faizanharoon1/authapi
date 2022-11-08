using AutoMapper;
using DAL;
using Microsoft.AspNetCore.Mvc;
using WebApi.Models.Users;
using WebApi.Services;

namespace WebApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsersController : BaseController
    {
        private readonly IUserService _UserService;
        private readonly IMapper _mapper;

        public UsersController(
            IUserService UserService,
            IMapper mapper)
        {
            _UserService = UserService;
            _mapper = mapper;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate(AuthenticateRequest model)
        {
            try
            {
                var response = await _UserService.Authenticate(model, ipAddress());
                setTokenCookie("refreshToken", response.RefreshToken);

                return Ok(response);
            }
            catch (Exception ex)
            {

                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthenticateResponse>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest(new { message = "RefreshToken is required" });

            var response = await _UserService.RefreshToken(refreshToken, ipAddress());
            setTokenCookie("refreshToken", response.RefreshToken);
            return Ok(response);
        }

        [Authorize]
        [HttpPost("revoke-token")]
        public IActionResult RevokeToken(RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            // users can revoke their own tokens and admins can revoke any tokens
            if (!user.OwnsToken(token) && user.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            _UserService.RevokeToken(token, ipAddress());
            return Ok(new { message = "Token revoked" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest model)
        {
            try
            {
                await _UserService.Register(model, Request.Headers["origin"]);
                return Ok(new { message = "Registration successful, please check your email for verification instructions" });
            }
            catch (Exception ex)
            {

                return BadRequest(new { message = ex.Message });
            }

        }

        [HttpPost("verify-email")]
        public IActionResult VerifyEmail(VerifyEmailRequest model)
        {
            _UserService.VerifyEmail(model);
            return Ok(new { message = "Verification successful, you can now login" });
        }

        [HttpPost("forgot-password")]
        public IActionResult ForgotPassword(ForgotPasswordRequest model)
        {
            _UserService.ForgotPassword(model, Request.Headers["origin"]);
            return Ok(new { message = "Please check your email for password reset instructions" });
        }

        [HttpPost("validate-reset-token")]
        public IActionResult ValidateResetToken(ValidateResetTokenRequest model)
        {
            _UserService.ValidateResetToken(model);
            return Ok(new { message = "Token is valid" });
        }

        [HttpPost("reset-password")]
        public IActionResult ResetPassword(ResetPasswordRequest model)
        {
            _UserService.ResetPassword(model);
            return Ok(new { message = "Password reset successful, you can now login" });
        }

        [Authorize(Role.Admin)]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserResponse>>> GetAll()
        {
            //try
            //{
            //    var Users = await _UserService.GetAll();
            //    return Ok(Users);
            //}
            //catch (Exception ex)
            //{

            //    return BadRequest(new { message = ex.Message });
            //}
            return null;

        }
        [Authorize]
        [HttpGet("me/{id:guid}")]
        public async Task<ActionResult<UserResponse>> GetById(Guid id)
        {
            // users can get their own User and admins can get any User
            if (id != user.UserGuid)
                return Unauthorized(new { message = "Unauthorized" });

            var User = await _UserService.GetById(id);
            return Ok(User);
        }
        [Authorize]
        [HttpGet("{id:int}")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public ActionResult<UserResponse> GetById(int id)
        {
            // users can get their own User and admins can get any User
            if (id != user.Id && user.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var User = _UserService.GetById(id);
            return Ok(User);
        }

        [Authorize(Role.Admin)]
        [HttpPost]
        public ActionResult<UserResponse> Create(CreateRequest model)
        {
            var User = _UserService.Create(model);
            return Ok(User);
        }

        [Authorize]
        [HttpPut("{id:int}")]
        public ActionResult<UserResponse> Update(int id, UpdateRequest model)
        {
            // users can update their own User and admins can update any User
            if (id != user.Id && user.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            // only admins can update role
            if (user.Role != Role.Admin)
                model.Role = null;

            var User = _UserService.Update(id, model);
            return Ok(User);
        }

        [Authorize]
        [HttpDelete("{id:int}")]
        public IActionResult Delete(int id)
        {
            // users can delete their own User and admins can delete any User
            if (id != user.Id && user.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            _UserService.Delete(id);
            return Ok(new { message = "User deleted successfully" });
        }

        // helper methods

        private void setTokenCookie(string cookieName, string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddHours(1),
                SameSite=SameSiteMode.None,
                Secure=true
            };
            Response.Cookies.Append(cookieName, token, cookieOptions);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
