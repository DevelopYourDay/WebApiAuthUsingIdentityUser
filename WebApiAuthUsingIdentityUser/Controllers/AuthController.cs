using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApiAuthUsingIdentityUser.Dtos.Account;
using WebApiAuthUsingIdentityUser.Dtos.Auth;
using WebApiAuthUsingIdentityUser.Models;
using WebApiAuthUsingIdentityUser.Services;

namespace WebApiAuthUsingIdentityUser.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {

        private IAuthService _authService;
        private readonly IMapper _mapper;

        public AuthController(
           IAuthService authService,
      IMapper mapper)
        {
            _authService = authService;
            _mapper = mapper;
        }


        [HttpPost("create")]
        [AllowAnonymous]
        public async Task<IActionResult> Create([FromBody] CreateAccountDto model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            //map dto to entity
            var userEntity = _mapper.Map<UserEntity>(model);

            return await _authService.Create(userEntity, model.Password);

        }

        // POST: /Account/login
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginAccountDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            //map dto to entity
            var userEntity = _mapper.Map<UserEntity>(model);

            return await _authService.Login(userEntity, model.Password);

        }

        // POST: /Account/logout
        [HttpPost("logout")]
        public async Task<IActionResult> LogOut([FromBody] LogoutDto model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            var userEntity = _mapper.Map<UserEntity>(model);

            return await _authService.LogOut(model.RefreshToken);
        }

        [HttpPost("newToken")]
        [AllowAnonymous]
        public async Task<IActionResult> Token([FromBody] CreateNewTokenDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            var userEntity = _mapper.Map<UserEntity>(model);

            return await _authService.CreateToken(userEntity, model.Password, model.RefreshToken);

        }
    }
}