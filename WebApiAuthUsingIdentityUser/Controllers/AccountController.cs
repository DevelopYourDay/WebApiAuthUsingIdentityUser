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

        public AccountController(IAccountService accountService, IMapper mapper)
        {
            _accountService = accountService;
            _mapper = mapper;
        }


        // GET: /Account/
        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _accountService.GetAll();
            var userDtos = _mapper.Map<IList<GetAllAccountsDto>>(users);
            return Ok(userDtos);

        }

        [HttpPut("updatePassword/{id}")]
        public async Task<IActionResult> UpdatePassword(string id, [FromBody]UpdateUserPasswordDto updateUserPasswordDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                // save 
                await _accountService.UpdatePasswordAsync(updateUserPasswordDto, id);
                return Ok(new { message = "Password alterada com sucesso!" });
            }
            catch (AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        //get user by Email or Id our Username
        [HttpGet ("getuserby/{userparms}")]
        public IActionResult GetUserBy(string userparms)
        {
            try
            {
                // save 
                var user = _accountService.GetUserByIdOrEmailOrUsername(userparms);
                return Ok(user);
            }
            catch (AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("requestUpdateEmail/{id}")]
        public async Task<IActionResult> RequestUpdateEmailAsync(string id, [FromBody]UpdateUSerEmailAccountDto updateUserPasswordDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                // save 
               await  _accountService.RequestUpdateEmail(updateUserPasswordDto, id, Url);
                return Ok(new { message = "Por favor consulte o seu email para confirmar a alteração!" });
            }
            catch (AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }


        [AllowAnonymous]
        [HttpPost("ChangeEmailToken")]
        public async Task<RedirectResult> UpdateEmailConfirmationTokenAsync([FromQuery] string token, [FromQuery] string userId, [FromQuery] string newEmail)
        {
            try
            {
                await _accountService.UpdateEmailConfirmationToken(token, userId, newEmail);
                return RedirectPermanent("https://www.google.com");
            }
            catch (AppException )
            {
                return RedirectPermanent("https://www.sapo.com");
            }
        }

        
        [HttpPut("ChangeUserProfile/{id}")]
        public async Task<IActionResult> UpdateUserProfile(string id, [FromBody]UpdateUserAccountDto updateUserAccountDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                // save 
                await _accountService.UpdateUserAccountAsync(updateUserAccountDto, id);
                return Ok(new { message = "Dados do utilizador alterados com sucesso!" });
            }
            catch (AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

    }
}