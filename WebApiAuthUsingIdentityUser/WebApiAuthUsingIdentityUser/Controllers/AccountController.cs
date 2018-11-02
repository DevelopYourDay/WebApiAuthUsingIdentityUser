using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebApiAuthUsingIdentityUser.Models;
using WebApiAuthUsingIdentityUser.Dtos;
using WebApiAuthUsingIdentityUser.Services;
using WebApiAuthUsingIdentityUser.Helpers;
using WebApiAuthUsingIdentityUser.Dtos.Account;
using AutoMapper;

namespace WebApiAuthUsingIdentityUser.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/Account")]
    public class AccountController : ControllerBase
    {
        private IAccountService _accountService;
        private readonly IMapper _mapper;

        public AccountController(
            IAccountService accountService,
            IMapper mapper)
        {
            _accountService = accountService;
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

            return await _accountService.Create(userEntity, model.Password);

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

            return await _accountService.Login(userEntity, model.Password);

        }

        [HttpPost("token")]
        [AllowAnonymous]
        public async Task<IActionResult> Token([FromBody] TokenAccountDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            var userEntity = _mapper.Map<UserEntity>(model);

            return await _accountService.Token(userEntity, model.Password);

        }

        // POST: /Account/logout
        [HttpPost("logout")]
        public async Task<IActionResult> LogOut()
        {
            return await _accountService.LogOut();
        }


        // GET: /Account/
        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _accountService.GetAll();
            var userDtos = _mapper.Map<IList<GetAllAccountsDto>>(users);
            return Ok(userDtos);

        }
    }
}