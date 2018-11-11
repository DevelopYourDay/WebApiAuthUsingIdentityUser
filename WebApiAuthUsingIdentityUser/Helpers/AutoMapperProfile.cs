using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using WebApiAuthUsingIdentityUser.Dtos.Auth;
using WebApiAuthUsingIdentityUser.Dtos.Account;
using WebApiAuthUsingIdentityUser.Models;


namespace WebApiAuthUsingIdentityUser.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            // Auth Mappers
            CreateMap<UserEntity, CreateAccountDto>();
            CreateMap<CreateAccountDto, UserEntity>();

            CreateMap<UserEntity, LoginAccountDto>();
            CreateMap<LoginAccountDto, UserEntity>();

            CreateMap<UserEntity, CreateNewTokenDto>();
            CreateMap<CreateNewTokenDto, UserEntity>();

            CreateMap<UserEntity, LogoutDto>();
            CreateMap<LogoutDto, UserEntity>();

            // Account Mappers
            CreateMap<UserEntity, UpdateUserPasswordDto>();
            CreateMap<UpdateUserPasswordDto, UserEntity>();

            CreateMap<UserEntity, GetAllAccountsDto>();
            CreateMap<GetAllAccountsDto, UserEntity>();


            CreateMap<UserEntity, GetUserByEmailOrIdOrUsernameDto>();
            CreateMap<GetUserByEmailOrIdOrUsernameDto, UserEntity>();

            CreateMap<UserEntity, UpdateUserAccountDto>();
            CreateMap<UpdateUserAccountDto, UserEntity>();

        }
    }
}