using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApiAuthUsingIdentityUser.Helpers.Jwt.Models;
using WebApiAuthUsingIdentityUser.Models;

namespace WebApiAuthUsingIdentityUser.Data
{
    public class DataContext : IdentityDbContext<UserEntity>
    {

        public DataContext(DbContextOptions<DataContext> options): base(options){}

        public DbSet<RefreshTokens> RefreshTokens { get; set; }

    }
}
