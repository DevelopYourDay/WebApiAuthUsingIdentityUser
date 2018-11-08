using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApiAuthUsingIdentityUser.Data;
using WebApiAuthUsingIdentityUser.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using WebApiAuthUsingIdentityUser.Helpers;
using WebApiAuthUsingIdentityUser.Helpers.Jwt.Models;
using Microsoft.AspNetCore.Http;

namespace WebApiAuthUsingIdentityUser.Services
{

    public interface IAuthService
    {

        Task<IActionResult> Create(UserEntity model, string password);

        Task<IActionResult> Login(UserEntity model, string password);

        Task<IActionResult> LogOut(string RefreshToken);

        Task<IActionResult> CreateToken([FromBody] UserEntity model, string password, string refreshtoken);
    }

    public class AuthService : ControllerBase, IAuthService
    {

        private DataContext _context;
        private readonly UserManager<UserEntity> _userManager;
        private readonly SignInManager<UserEntity> _signInManager;
        private readonly IPasswordHasher<UserEntity> _passwordHasher;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContext;


        public AuthService(
         DataContext context,
         UserManager<UserEntity> userManager,
         SignInManager<UserEntity> signInManager,
         IPasswordHasher<UserEntity> passwordHasher,
         IConfiguration configuration,
          IHttpContextAccessor httpContext)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordHasher = passwordHasher;
            _configuration = configuration;
            _httpContext = httpContext;
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
                    throw new AppException("UserName [ " + model.UserName + " ] is already used");

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
                if (user == null || _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password) != PasswordVerificationResult.Success)
                {
                    return BadRequest(new { message = "Wrong user or password!" });
                }

                var token = await GetJwtSecurityToken(user);
                if (token == null)
                {
                    return BadRequest(new { message = "Error generating Token" });
                }

                var refreshToken = new RefreshTokens
                {
                    Username = user.UserName,
                    Token = GenerateRefreshToken(user).Token,
                    Revoked = false,
                    IpAdress = _httpContext.HttpContext.Connection.RemoteIpAddress.ToString(),
                };

                _context.RefreshTokens.Add(refreshToken);
                _context.SaveChanges();

                return Ok(new
                {
                    message = "Login Successful!",
                    access_token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    refresh_token = refreshToken.Token,

                });

            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        public async Task<IActionResult> LogOut(string RefreshToken)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                if (!_context.RefreshTokens.Any(x => x.Token == RefreshToken))
                {
                    // error 400
                    return BadRequest(new { message = "Invalid Refresh Token!" });
                }

                RefreshTokens NewRefreshToken = _context.RefreshTokens.Single(x => x.Token == RefreshToken);

                NewRefreshToken.Revoked = true;

                _context.RefreshTokens.Update(NewRefreshToken);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    message = " logout succssesfully done"
                });

            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        public async Task<IActionResult> CreateToken([FromBody] UserEntity model, string password, string refreshToken)
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
                // generate token
                var token = await GetJwtSecurityToken(user);

                // Checks the old refreshToken exists is valid and exists
                if (!_context.RefreshTokens.Any(x => x.Username == model.UserName && x.Revoked == false && x.Token == refreshToken))
                {
                    // error 400
                    return BadRequest(new { message = "Wrong parameters!" });
                }

                // generate token refresh token
                RefreshTokens NewRefreshToken = GenerateRefreshToken(user);

                //Update refreshToken
                RefreshTokens oldRefreshToken = _context.RefreshTokens.Single(
                    x => x.Username == model.UserName && x.Revoked == false && x.Token == refreshToken);
                if (oldRefreshToken == null)
                {
                    // error 400
                    return BadRequest(new { message = "Wrong parameters oldRefreshToken!" });
                }

                var resultRemove = _context.RefreshTokens.Remove(oldRefreshToken);
                var resultAdd =  _context.RefreshTokens.AddAsync(NewRefreshToken);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(token),
                    expires_in = token.ValidTo,
                    refresh_token = NewRefreshToken.Token
                });

            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
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

        private RefreshTokens GenerateRefreshToken(UserEntity user)
        {
           var result= _passwordHasher.HashPassword(user, Guid.NewGuid().ToString())
                  .Replace("+", string.Empty)
                  .Replace("=", string.Empty)
                  .Replace("/", string.Empty);

           
               var refreshToken = new RefreshTokens
                {
                    Username = user.UserName,
                    Token = result,
                    Revoked = false,
                    IpAdress = _httpContext.HttpContext.Connection.RemoteIpAddress.ToString(),
                };
       
            return refreshToken;
        }
    }
}
