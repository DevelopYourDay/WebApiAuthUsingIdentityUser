using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApiAuthUsingIdentityUser.Dtos.Account
{
    public class GetUserByEmailOrIdOrUsernameDto
    {
        [Required]
        [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 3)]
        [Display(Name = "UserName")]
        public string UserName { get; set; }
        [Required]
        [EmailAddress(ErrorMessage = "The email is not valid")]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 3)]
        public string FirstName { get; set; }
        [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 3)]
        public string LastName { get; set; }
    }
}
