using DAL;
using Microsoft.AspNetCore.Mvc;
using DAL.Entities;

namespace WebApi.Controllers
{
    [Controller]
    public abstract class BaseController : ControllerBase
    {
        // returns the current authenticated User (null if not logged in)
        public User user => (User)HttpContext.Items["User"];
    }
}
