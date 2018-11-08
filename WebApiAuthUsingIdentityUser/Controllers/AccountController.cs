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
        public IActionResult UpdatePassword(string id, [FromBody]UserUpdatePasswordDto updateUserPasswordDto)
        {
            try
            {
                // save 
                _accountService.UpdatePassword(updateUserPasswordDto, id);
                return Ok(new { message = "Password alterada com sucesso!" });
            }
            catch (AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}