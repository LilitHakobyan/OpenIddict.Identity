using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthorizationServer.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer.Controllers
{
    /// <summary>
    /// Account controller for interacting with login form
    /// </summary>
    public class AccountController : Controller
    {
        /// <summary>
        /// Action serves the login form
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            // save in view data so we can use this to redirect the user after a successful login
            ViewData["ReturnUrl"] = returnUrl;

            // return login view
            return View();
        }

        /// <summary>
        /// Login validation and redirection logic 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            ViewData["ReturnUrl"] = model.ReturnUrl;

            // this would be the place where you check the credentials , in this example any combination is valid
            // so i will only check if ModelState is valid ( That means that a username and a password are required)
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // when the ModelState is valid 
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, model.Username)
            };

            // specify the cookie authentication scheme
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            //calls the AuthenticationService which calls the CookieAuthenticationHandler because that's the scheme we specified when creating the claims identity.
            await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));

            // after signing in we need to redirect the user
            // check if it's a local url to prevent open redirect attacks before redirecting
            if (Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            // otherwise the user is redirected to the home page
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        /// <summary>
        /// Logout action 
        /// </summary>
        /// <returns></returns>
        public async Task<IActionResult> Logout()
        {
            // calls the authentication service to sign out the user
            // the authentication service will call the authentication middleware, in our case the cookie authentication middleware, to sign out the user
            await HttpContext.SignOutAsync();

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
