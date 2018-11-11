using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using WebApiAuthUsingIdentityUser.Controllers;
using WebApiAuthUsingIdentityUser.Data;
using WebApiAuthUsingIdentityUser.Dtos.Account;
using WebApiAuthUsingIdentityUser.Helpers;
using WebApiAuthUsingIdentityUser.Helpers.Jwt.Models;
using WebApiAuthUsingIdentityUser.Models;
namespace WebApiAuthUsingIdentityUser.Services
{

    public interface IAccountService
    {
        IEnumerable<UserEntity> GetAll();

        Task UpdatePasswordAsync(UpdateUserPasswordDto userUpdatePasswordDto, string idUser);

        GetUserByEmailOrIdOrUsernameDto GetUserByIdOrEmailOrUsername(string userParams);

        Task RequestUpdateEmail(UpdateUSerEmailAccountDto userParams, string idUser, IUrlHelper url);

        Task UpdateEmailConfirmationToken(string token, string userID, string newEmail);

        Task UpdateUserAccountAsync(UpdateUserAccountDto userParams, string idUser);
    }

    public class AccountService : ControllerBase, IAccountService
    {

        private DataContext _context;
        private readonly UserManager<UserEntity> _userManager;
        private readonly SignInManager<UserEntity> _signInManager;
        private readonly IPasswordHasher<UserEntity> _passwordHasher;
        private readonly IConfiguration _configuration;
        private readonly IAuthService _authService;
        private readonly IHttpContextAccessor _httpContext;
        private readonly IMapper _mapper;


        public AccountService(
          DataContext context,
          UserManager<UserEntity> userManager,
          SignInManager<UserEntity> signInManager,
          IPasswordHasher<UserEntity> passwordHasher,
          IConfiguration configuration,
          IAuthService authService,
          IHttpContextAccessor httpContextAccessor,
          IMapper mapper)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordHasher = passwordHasher;
            _configuration = configuration;
            _authService = authService;
            _httpContext = httpContextAccessor;
            _mapper = mapper;
        }


        public IEnumerable<UserEntity> GetAll()
        {
            return _context.Users;
        }

        public async Task UpdatePasswordAsync(UpdateUserPasswordDto userUpdatePasswordDto, string idUser)
        {
            if (userUpdatePasswordDto.OldPassword.Equals(userUpdatePasswordDto.NewPassword))
                throw new AppException("The old password is the same as the new password. Then the password does not need to be changed.");

            var user = _context.Users.Find(idUser);
                if (user == null)
                    throw new AppException("User not found");

            if ( _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, userUpdatePasswordDto.OldPassword) != PasswordVerificationResult.Success)
                throw new AppException("OldPassword wrong!");

           var result = await _userManager.ChangePasswordAsync(user, userUpdatePasswordDto.OldPassword, userUpdatePasswordDto.NewPassword);
            if(!result.Succeeded)
                throw new AppException("Um problema alterar a password!");

        }


        public GetUserByEmailOrIdOrUsernameDto GetUserByIdOrEmailOrUsername(string userParams)
        {
            if (userParams == null)
                throw new AppException("Id or email or username not found!");

            var userEntity = _context.Users.Where(x => x.Id == userParams || x.Email == userParams || x.UserName == userParams).FirstOrDefault();
            if (userEntity == null)
                throw new AppException("User not found!");

            var user = _mapper.Map<GetUserByEmailOrIdOrUsernameDto>(userEntity);
            if (user == null)
                throw new AppException("User not found!");
            return user;
        }


        public async Task UpdateUserAccountAsync(UpdateUserAccountDto userParams, string idUser)
        {
                if (userParams == null)
                    throw new AppException("The data provided is not correct");

            var user = await _userManager.FindByIdAsync(idUser);
                if (user == null)
                    throw new AppException("Não existe registo do utilizador!");

            var userEntityUsername = await _userManager.FindByNameAsync(userParams.UserName);
                 if (userEntityUsername != null)
                    throw new AppException("Username is already assigned to another user!");

            user.UserName = userParams.UserName;
            user.FirstName = userParams.FirstName;
            user.LastName = userParams.LastName;

           var resultUpdateUser =  await _userManager.UpdateAsync(user);
            if (!resultUpdateUser.Succeeded)
                throw new AppException("Pedimos desculpa mas ocorreu um problema ao actualizar a sua conta. Tente novamente mais tarde!.");
        }

        public async Task RequestUpdateEmail(UpdateUSerEmailAccountDto userParams, string idUser, IUrlHelper url)
        { 
                if (userParams == null || idUser == null)
                    throw new AppException("The data provided is not correct");

                var user = await _userManager.FindByIdAsync(idUser);
                    if (user == null)
                        throw new AppException("Utilizador Invalido!");

                //if (userParams.Email.Equals(user.Email, StringComparison.InvariantCultureIgnoreCase))
                //    throw new AppException("O seu novo email e o mesmo da sua actual conta! Por favor indique um email diferente.");

                //var userEntityUsername = await _userManager.FindByEmailAsync(userParams.Email);
                //    if (userEntityUsername != null)
                //        throw new AppException("Email is already assigned to another user!");

                var token = await _userManager.GenerateChangeEmailTokenAsync(user, userParams.Email);

                var resetLink = url.Action("UpdateEmailConfirmationTokenAsync", "Account", 
                    new { token = token, userId = user.Id, newEmail = userParams.Email }, protocol: _httpContext.HttpContext.Request.Scheme);

                    Helpers.SendGrid sendEmail = new Helpers.SendGrid(_configuration);

                     await sendEmail.PostMessageUpdateEmail(userParams.Email, resetLink);
        }

        public async Task UpdateEmailConfirmationToken(string token, string userID, string newEmail)
        {
            var user = await _userManager.FindByIdAsync(userID);
                 if (user == null)
                    throw new AppException("Utilizador Invalido!");

            var changeEmail = await _userManager.ChangeEmailAsync(user, newEmail, token);
                if (!changeEmail.Succeeded)
                    throw new AppException("Um erro ocorreu a Alterar o email!");    
        }
    }
}
