using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using WebApiAuthUsingIdentityUser.Dtos.Account;
using WebApiAuthUsingIdentityUser.Models;


namespace WebApiAuthUsingIdentityUser.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            // Account Mappers
            CreateMap<UserEntity, CreateAccountDto>();
            CreateMap<CreateAccountDto, UserEntity>();

            CreateMap<UserEntity, LoginAccountDto>();
            CreateMap<LoginAccountDto, UserEntity>();

            CreateMap<UserEntity, TokenAccountDto>();
            CreateMap<TokenAccountDto, UserEntity>();

            CreateMap<UserEntity, GetAllAccountsDto>();
            CreateMap<GetAllAccountsDto, UserEntity>();
        }
    }
}