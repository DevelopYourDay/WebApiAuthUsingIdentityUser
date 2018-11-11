using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApiAuthUsingIdentityUser.Dtos.Account;
using WebApiAuthUsingIdentityUser.Dtos.Auth;
using WebApiAuthUsingIdentityUser.Helpers;
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
            try
            {

                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                //map dto to entity
                var userEntity = _mapper.Map<UserEntity>(model);

                await _authService.Create(model, Url);

                return Ok(new { message = "Registered User Successfully!" });

            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }


        }

        // POST: /Account/login
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginAccountDto model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
                }

                return await _authService.Login(model);
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // POST: /Account/logout
        [HttpPost("logout")]
        public async Task<IActionResult> LogOut([FromBody] LogoutDto model)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());

                await _authService.LogOut(model.RefreshToken);

                return Ok(new { message = " logout succssesfully done" });

            }
            catch (AppException ex) { return BadRequest(new { message = ex.Message }); }
        }

        // POST: /Account/newToken
        [HttpPost("newToken")]
        [AllowAnonymous]
        public async Task<IActionResult> Token([FromBody] CreateNewTokenDto model)
        {

            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());

                var userEntity = _mapper.Map<UserEntity>(model);

                return await _authService.CreateToken(model);
            }
            catch (AppException ex) { return BadRequest(new { message = ex.Message }); }

        }

        [HttpGet("EmailConfirmation")]
        [AllowAnonymous]
        public async Task<RedirectResult> EmailConfirmationAfterRegistration([FromQuery] string token, [FromQuery] string email)
        {
            try
            {
                await _authService.EmailConfirmationAfterRegistration(token, email);
                return RedirectPermanent("https://www.google.com");
            }
            catch (AppException)
            {
                return RedirectPermanent("https://www.sapo.com");
            }
        }

        [HttpPost("EmailForwardingForRegistrationConfirmation")]
        [AllowAnonymous]
        public async Task<IActionResult> EmailForwardingForRegistrationConfirmation([FromBody] EmailForwardingForRegistrationConfirmationDto model)
        {
            try
            {

                if (!ModelState.IsValid)
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());

                await _authService.SendEmailFromConfirmation(model.Email, Url);
                return Ok(new { message = "Email enviado com sucesso. Por favor consultar a sua caixa de email!" });
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }


        [HttpPost("ForgetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgetPassword([FromBody] ForgetPasswordDto modelDto)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());

                await _authService.SendEmailForgetPassword(modelDto, Url);
                return Ok(new { message = "Por favior siga as instruções enviadas para o seu email.\n Obrigado!" });
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }


        [HttpPost("NewPasswordFromForgetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> NewPasswordFromForgetPassword([FromQuery] string token, [FromQuery] string id, [FromBody] NewPasswordDto newPasswordDto)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());

                await _authService.NewPasswordAfterForgetPassword(newPasswordDto, token, id);
                return Ok(new { message = "Password Alterada Com sucesso!" });
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}