using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WebApiAuthUsingIdentityUser.Controllers;
using WebApiAuthUsingIdentityUser.Data;
using WebApiAuthUsingIdentityUser.Dtos.Account;
using WebApiAuthUsingIdentityUser.Helpers;
using WebApiAuthUsingIdentityUser.Models;

namespace WebApiAuthUsingIdentityUser.Services
{

    public interface IAccountService
    {
        Task<IActionResult> Create(UserEntity model, string password);
        Task<IActionResult> Login(UserEntity model, string password);
        Task<IActionResult> LogOut();

        Task<IActionResult> Token([FromBody] UserEntity model, string password);

        IEnumerable<UserEntity> GetAll();
    }

    public class AccountService : ControllerBase, IAccountService
    {

        private DataContext _context;
        private readonly UserManager<UserEntity> _userManager;
        private readonly SignInManager<UserEntity> _signInManager;
        private readonly IPasswordHasher<UserEntity> _passwordHasher;
        private readonly IConfiguration _configuration;

        public AccountService(
          DataContext context,
          UserManager<UserEntity> userManager,
          SignInManager<UserEntity> signInManager,
          IPasswordHasher<UserEntity> passwordHasher,
          IConfiguration configuration)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordHasher = passwordHasher;
            _configuration = configuration;
        }


        public async Task<IActionResult> Create(UserEntity model, string password)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                if (_context.Users.Any(x => x.UserName == model.UserName))
                    throw  new AppException("UserName [ " + model.UserName + " ] is already used");

                var user = new UserEntity { UserName = model.UserName, Email = model.Email };

                var result = await _userManager.CreateAsync(user, password);

                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors.Select(x => x.Description).ToList());
                }

                await _signInManager.SignInAsync(user, false);
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }

            return Ok(new { message = "Registered User Successfully!" });
        }


        public async Task<IActionResult> Login(UserEntity model, string password)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                var result = await _signInManager.PasswordSignInAsync(model.UserName, password, isPersistent: false, lockoutOnFailure: false);

                if (!result.Succeeded)
                {
                    return BadRequest(new { message = "Wrong user or password!" });
                }

                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user == null ||
                _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password) !=
                PasswordVerificationResult.Success)
                {
                    return BadRequest(new { message = "Error generating Token. Send a message to the administrator for more information!" });
                }
                var token = await GetJwtSecurityToken(user);

                return Ok(new { message = "Login Successful!",
                               token = new JwtSecurityTokenHandler().WriteToken(token),
                               expiration = token.ValidTo
                });

            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }


        public async Task<IActionResult> LogOut()
        {
            try
            {
                await _signInManager.SignOutAsync();
                return Ok(new { message = "Logout done successfully!" });
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        public async Task<IActionResult> Token([FromBody] UserEntity model, string password)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }


                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user == null ||
                _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password) !=
                PasswordVerificationResult.Success)
                {
                    return BadRequest(new { message = "Wrong user or password!" });
                }
                var token = await GetJwtSecurityToken(user);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });

            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        public IEnumerable<UserEntity> GetAll()
        {
            return _context.Users;
        }


        private async Task<JwtSecurityToken> GetJwtSecurityToken(UserEntity user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            return new JwtSecurityToken(
            issuer: _configuration.GetValue<string>("AppConfiguration:SiteUrl"),
            audience: _configuration.GetValue<string>("AppConfiguration:SiteUrl"),
            claims: GetTokenClaims(user).Union(userClaims),
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            _configuration.GetValue<string>("AppConfiguration:Key"))),
            SecurityAlgorithms.HmacSha256)
            );
        }

        private static IEnumerable<Claim> GetTokenClaims(UserEntity user)
        {
            return new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName)
            };
        }

    }
}
