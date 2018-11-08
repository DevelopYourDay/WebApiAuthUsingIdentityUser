using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using WebApiAuthUsingIdentityUser.Models;

namespace WebApiAuthUsingIdentityUser.Helpers.Jwt.Models
{
    public class RefreshTokens : Trackable
    {
        [Key]
        public string Id { get; set; }

        [Required]
        [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 3)]
        public string Username { get; set; }
        [Required]
        public string Token { get; set; }
        [Required]
        public string IpAdress { get; set; }
        [Required]
        public bool Revoked { get; set; }

    }
}
