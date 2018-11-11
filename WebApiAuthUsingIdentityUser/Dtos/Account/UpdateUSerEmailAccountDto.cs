using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApiAuthUsingIdentityUser.Dtos.Account
{
    public class UpdateUSerEmailAccountDto
    {
        [Required]
        [EmailAddress(ErrorMessage = "The email is not valid")]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare("Email", ErrorMessage = "The Email and confirmation Email do not match.")]
        public string EmailConfirmation { get; set; }
    }
}
