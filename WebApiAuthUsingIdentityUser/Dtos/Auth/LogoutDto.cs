﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;



namespace WebApiAuthUsingIdentityUser.Dtos.Auth
{
    public class LogoutDto
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
