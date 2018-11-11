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
using WebApiAuthUsingIdentityUser.Dtos.Auth;
using AutoMapper;
using Microsoft.EntityFrameworkCore;

namespace WebApiAuthUsingIdentityUser.Services
{

    public interface IAuthService
    {

        Task Create(CreateAccountDto model, IUrlHelper url);

        Task<IActionResult> Login(LoginAccountDto model);

        Task LogOut(string RefreshToken);

        Task<IActionResult> CreateToken(CreateNewTokenDto model);

        Task EmailConfirmationAfterRegistration(string token, string email);

        Task SendEmailFromConfirmation(string email, IUrlHelper url);

        Task SendEmailForgetPassword(ForgetPasswordDto forgetPasswordDto, IUrlHelper url);

        Task NewPasswordAfterForgetPassword(NewPasswordDto forgetPasswordDto, string token, string email);
    }

    public class AuthService : ControllerBase, IAuthService
    {

        private DataContext _context;
        private readonly UserManager<UserEntity> _userManager;
        private readonly SignInManager<UserEntity> _signInManager;
        private readonly IPasswordHasher<UserEntity> _passwordHasher;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContext;
        private readonly IMapper _mapper;


        public AuthService(
         DataContext context,
         UserManager<UserEntity> userManager,
         SignInManager<UserEntity> signInManager,
         IPasswordHasher<UserEntity> passwordHasher,
         IConfiguration configuration,
         IHttpContextAccessor httpContext,
         IMapper mapper)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordHasher = passwordHasher;
            _configuration = configuration;
            _httpContext = httpContext;
            _mapper = mapper;
        }

        public async Task Create(CreateAccountDto model, IUrlHelper url)
        {
            var resultFindUserByUsername = await _userManager.FindByNameAsync(model.UserName);
            if (resultFindUserByUsername != null)
                throw new AppException("UserName [ " + model.UserName + " ] is already used");

            var resultFindUserByEmail = await _userManager.FindByEmailAsync(model.Email);
            if (resultFindUserByEmail != null)
                throw new AppException("Email [ " + model.Email + " ] is already used");

            var userEntity = _mapper.Map<UserEntity>(model);

            var result = await _userManager.CreateAsync(userEntity, model.Password);
            if (!result.Succeeded)
                throw new AppException(result.Errors.Select(x => x.Description).ToList());

            await SendEmailFromConfirmation(userEntity.Email, url);
        }

        public async Task<IActionResult> Login(LoginAccountDto model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
                if (user == null)
                    throw new AppException("Wrong user or password!");

            var emailConfirmation = await _userManager.IsEmailConfirmedAsync(user);
                if (emailConfirmation == false)
                    throw new AppException("Precisas de confirmar o teu registo para continuar. Por favor confirma o teu email!");
     

            var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, isPersistent: false, lockoutOnFailure: true);
                //if (!result.Succeeded)
                //  throw new AppException("Wrong user or password!");

            await UserIsLockoutAsync(user, result);

            await _userManager.ResetAccessFailedCountAsync(user);


            var token = await GetJwtSecurityToken(user);
            if (token == null)
                throw new AppException("Error generating Token!");

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

        public async Task LogOut(string RefreshToken)
        {
            if (!_context.RefreshTokens.Any(x => x.Token == RefreshToken))
                throw new AppException("Invalid Refresh Token!");
            try
            {
                RefreshTokens NewRefreshToken = _context.RefreshTokens.Single(x => x.Token == RefreshToken);
                NewRefreshToken.Revoked = true;

                _context.RefreshTokens.Update(NewRefreshToken);
                await _context.SaveChangesAsync();
            }
            catch (ArgumentNullException) { throw new AppException("Nao foi encontrado nenhum token!"); }
            catch (InvalidOperationException) { throw new AppException("Existe mais que um token!"); }
            catch (DbUpdateException) { throw new AppException("Foi encontrado um erro ao gravar o token na base de dados!"); }
        }

        public async Task<IActionResult> CreateToken(CreateNewTokenDto model)
        {

                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user == null || _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password) != PasswordVerificationResult.Success)
                    throw new AppException("Wrong user or password!");
               
                // generate token
                var token = await GetJwtSecurityToken(user);

                // Checks the old refreshToken exists is valid and exists
                if (!_context.RefreshTokens.Any(x => x.Username == model.UserName && x.Revoked == false && x.Token == model.RefreshToken))
                    throw new AppException("Wrong parameters!");    // error 400

                // generate token refresh token
                RefreshTokens NewRefreshToken = GenerateRefreshToken(user);

                //Update refreshToken
                RefreshTokens oldRefreshToken = _context.RefreshTokens.Single( x => x.Username == model.UserName && x.Revoked == false && x.Token == model.RefreshToken);
                if (oldRefreshToken == null)
                    throw new AppException("Wrong parameters oldRefreshToken!"); // error 400
                
                var resultRemove = _context.RefreshTokens.Remove(oldRefreshToken);
                var resultAdd = _context.RefreshTokens.AddAsync(NewRefreshToken);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(token),
                    expires_in = token.ValidTo,
                    refresh_token = NewRefreshToken.Token
                });

            
        }

        public async Task SendEmailFromConfirmation(string email, IUrlHelper url)
        {
            if(email == null)
                throw new AppException("Os dados para confirmar o email nao estao correctos!");

            var userEntity = await _userManager.FindByEmailAsync(email);
            if (userEntity == null)
                throw new AppException("Email [ " + email + " ] dont exist!");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(userEntity);
            if (token == null)
                throw new AppException("Erro ao gerar token para envio de email!");

            var emailConfirmationLink = url.Action("EmailConfirmationAfterRegistration", "Auth",
                new { token = token, email = email }, protocol: _httpContext.HttpContext.Request.Scheme);
            if (emailConfirmationLink == null)
                throw new AppException("Erro ao gerar link para confirmacao de email!");

            Helpers.SendGrid sendEmail = new Helpers.SendGrid(_configuration);
            var resulsendEmail = await sendEmail.PostMessageConfirmRegister(email, emailConfirmationLink);
            if (resulsendEmail.StatusCode != System.Net.HttpStatusCode.Accepted)
                throw new AppException("Foi impossivel enviar o email de confirmação! Por favor contactar um administrador");

        }

        public async Task EmailConfirmationAfterRegistration(string token, string email)
        {
            if(token == null || email == null)
                throw new AppException("Os dados para a confirmação de email nao estao corretos!");

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                throw new AppException("Utilizador Invalido!");

            var changeEmail = await _userManager.ConfirmEmailAsync(user, token);
            if (changeEmail.Succeeded)
            {
                var emailConfirmado = _userManager.IsEmailConfirmedAsync(user);
            }
            else
                throw new AppException("O Token nao e valido");

        }

        public async Task SendEmailForgetPassword(ForgetPasswordDto forgetPasswordDto, IUrlHelper url)
        {
            if (forgetPasswordDto.Email == null)
                throw new AppException("O Email é de preenchimento obrigatorio!");

            var userEntity = await _userManager.FindByEmailAsync(forgetPasswordDto.Email);
            if (userEntity == null)
                throw new AppException("Email [ " + forgetPasswordDto.Email + " ] dont exist!");

            var token = await _userManager.GeneratePasswordResetTokenAsync(userEntity);
            if (token == null)
                throw new AppException("Erro ao gerar password reset token!");

            var forgetPasswordLink = url.Action("NewPasswordFromForgetPassword", "Auth",
                new { token = token, id = userEntity.Id }, protocol: _httpContext.HttpContext.Request.Scheme);

            if (forgetPasswordLink == null)
                throw new AppException("Erro ao gerar link para confirmacao de email!");

            Helpers.SendGrid sendEmail = new Helpers.SendGrid(_configuration);
            var resulsendEmail = await sendEmail.PostMessageForgetPassword(userEntity.Email, forgetPasswordLink);
            if (resulsendEmail.StatusCode != System.Net.HttpStatusCode.Accepted)
                throw new AppException("Foi impossivel enviar o email para o reset a password! Por favor contactar um administrador");

        }
        

        public async Task NewPasswordAfterForgetPassword(NewPasswordDto forgetPasswordDto, string token, string id)
        {
            if (forgetPasswordDto.Password == null)
                throw new AppException("A password é de preenchimento obrigatorio!");

            if (token == null)
                throw new AppException("A Token não é valido!");

            if (id == null)
                throw new AppException("O id não é valido");

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                throw new AppException("Utilizador Invalido!");

            var resetPassword = await _userManager.ResetPasswordAsync(user, token, forgetPasswordDto.Password);
            if(!resetPassword.Succeeded)
                throw new AppException("Não foi possivel efectuar o reset a sua password. \nDos dados necessarios para realizar esta operação alguns nao se encontram corretos!");

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
            var result = _passwordHasher.HashPassword(user, Guid.NewGuid().ToString())
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

        private async Task UserIsLockoutAsync(UserEntity user, Microsoft.AspNetCore.Identity.SignInResult valideCredencials)
        {
            if (await _userManager.IsLockedOutAsync(user))
                throw new AppException("Your account has been locked out for {0} minutes due to multiple failed login attempts.", _userManager.Options.Lockout.DefaultLockoutTimeSpan);

            if(await _userManager.GetLockoutEnabledAsync(user) && !valideCredencials.Succeeded)
            {

                if (await _userManager.IsLockedOutAsync(user))
                    throw new AppException("Your account has been locked out for {0} minutes due to multiple failed login attempts.", _userManager.Options.Lockout.DefaultLockoutTimeSpan);

                
                    int accessFailedCount = await _userManager.GetAccessFailedCountAsync(user);

                    int attemptsLeft = _userManager.Options.Lockout.MaxFailedAccessAttempts - accessFailedCount;
                         throw new AppException("Invalid credentials. You have {0} more attempt(s) before your account gets locked out.", attemptsLeft);
            }

        }
    }
}
