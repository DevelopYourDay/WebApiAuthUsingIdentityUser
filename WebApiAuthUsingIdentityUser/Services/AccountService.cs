using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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

        void UpdatePassword(UserUpdatePasswordDto userUpdatePasswordDto, string idUser);
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


        public void UpdatePassword(UserUpdatePasswordDto userUpdatePasswordDto, string idUser)
        {
            if (!ModelState.IsValid)
            {
                throw new AppException(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            var user = _context.Users.Find(idUser);
            if (user == null)
                throw new AppException("User not found");

            if (_passwordHasher.VerifyHashedPassword(user, user.PasswordHash, userUpdatePasswordDto.OldPassword) != PasswordVerificationResult.Success)
                throw new AppException("OldPassword wrong!");

            // update password if it was entered
            if (!string.IsNullOrWhiteSpace(userUpdatePasswordDto.NewPassword))
            {
                var newPasswordHash = _passwordHasher.HashPassword(user, userUpdatePasswordDto.NewPassword);
                user.PasswordHash = newPasswordHash;
            }
            _context.Users.Update(user);
            _context.SaveChanges();
        }


    }
}
