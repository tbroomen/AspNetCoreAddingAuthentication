using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WishList.Models;
using WishList.Models.AccountViewModels;

namespace WishList.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register() 
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Register([FromBody] RegisterViewModel registerViewModel) 
        {
            if(!ModelState.IsValid) 
            {
                return View(registerViewModel);
            }

            var result = _userManager.CreateAsync(new ApplicationUser() 
                { UserName = registerViewModel.Email, Email = registerViewModel.Email }, registerViewModel.Password).Result;

            if(!result.Succeeded)
            {
                foreach(var error in result.Errors)
                {
                    ModelState.AddModelError("Password",error.Description);
                }

                return View(registerViewModel);
            }

            return RedirectToAction("Index","Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult Login([FromBody] LoginViewModel loginViewModel)
        {
            if (!ModelState.IsValid)
            {
                return View(loginViewModel);
            }

            var result = _signInManager.PasswordSignInAsync(loginViewModel.Email,loginViewModel.Password,false,false).Result;

            if(!result.Succeeded)
            {
                ModelState.AddModelError(String.Empty, "Invalid login attempt.");
            }

            return RedirectToAction("Index", "Item");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction("Index", "Home");
        }
    }
}
