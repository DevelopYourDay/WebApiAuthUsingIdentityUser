using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace WebApiAuthUsingIdentityUser.Models
{
    public class UserEntity : IdentityUser
    {

        /*
         * IdentityUser Have : 
         * 
         DateTimeOffset? LockoutEnd
         bool TwoFactorEnabled
         bool PhoneNumberConfirmed 
         string PhoneNumbe
         string ConcurrencyStamp
         string SecurityStamp
         string PasswordHash
         bool EmailConfirmed
         string NormalizedEmail
         string Email
         string NormalizedUserName
         string UserName
         TKey Id
         bool LockoutEnabled
         int AccessFailedCoun
         
         */
        [Key]
        public override string Id { get; set; }

        [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 3)]
        public string FirstName { get; set; }

        [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 3)]
        public string LastName { get; set; }

        public DateTime Inserted { get; private set; }

        public DateTime Updated { get; private set; }


    }
}
