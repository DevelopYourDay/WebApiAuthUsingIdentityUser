using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApiAuthUsingIdentityUser.Dtos.Auth
{
    public class ForgetPasswordDto
    {

        [Required]
        [EmailAddress(ErrorMessage = "The email is not valid")]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}
