using Microsoft.Extensions.Configuration;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace WebApiAuthUsingIdentityUser.Helpers
{
    public class SendGrid
    {
        private readonly IConfiguration _configuration;

        public SendGrid(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<Response> PostMessageConfirmRegister(string destinatario, string link)
        {
            var apiKey = _configuration.GetSection("SENDGRID_API_KEY").Value;
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("Developyourday@teste.com", "DevelopYourDay");
            EmailAddress to = new EmailAddress(destinatario);
            var subject = "Welcome to TesteAPI! Confirm Your Email";
            var htmlContent = "<strong>Hello world with HTML content</strong>\n <a href=" + link + ">Confirmar Email</a>.<br>";
            // var plainTextContent = "You're on your way! \nLet's confirm your email address. \n\n " +
            //"By clicking on the following link, you are confirming your email address. \n\n <a href="+link+">Confirmar Email</a>.<br>";

            var plainTextContent = "You're on your way! \nLet's confirm your email address. ";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            return await client.SendEmailAsync(msg);

        }


        public async Task<Response> PostMessageUpdateEmail(string destinatario, string link)
        {
            var apiKey = _configuration.GetSection("SENDGRID_API_KEY").Value;
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("Developyourday@teste.com", "DevelopYourDay");
            EmailAddress to = new EmailAddress(destinatario);
            var subject = "Develop your day - Required email change";
            var htmlContent = "<strong>An email change was requested in your account. the new email will be: " + destinatario + " \n\n To accept the change click <a href=" + link + ">here.</a>.<br>";
            // var plainTextContent = "You're on your way! \nLet's confirm your email address. \n\n " +
            //"By clicking on the following link, you are confirming your email address. \n\n <a href="+link+">Confirmar Email</a>.<br>";

            var plainTextContent = "You're on your way! \nLet's confirm your email address. ";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            return await client.SendEmailAsync(msg);

        }


        public async Task<Response> PostMessageForgetPassword(string destinatario, string link)
        {
            var apiKey = _configuration.GetSection("SENDGRID_API_KEY").Value;
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("Developyourday@teste.com", "DevelopYourDay");
            EmailAddress to = new EmailAddress(destinatario);
            var subject = "Develop your day - Forget your Password";
            var htmlContent = "<strong>PAssword forget. renew or password \n\n click <a href=" + link + ">here.</a>.<br>";
            // var plainTextContent = "You're on your way! \nLet's confirm your email address. \n\n " +
            //"By clicking on the following link, you are confirming your email address. \n\n <a href="+link+">Confirmar Email</a>.<br>";

            var plainTextContent = "You're on your way! \nLet's confirm your email address. ";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            return await client.SendEmailAsync(msg);

        }
    }
}
