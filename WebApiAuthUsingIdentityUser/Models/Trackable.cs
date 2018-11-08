using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApiAuthUsingIdentityUser.Models
{
    public abstract class Trackable
    {
        public DateTime Inserted { get; private set; }
        public DateTime Updated { get; private set; }
    }
}
