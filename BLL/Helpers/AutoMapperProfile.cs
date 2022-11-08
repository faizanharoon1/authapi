using AutoMapper;
using DAL;
using BLL.Models.Users;
using DAL.Entities;

namespace BLL.Helpers
{
    public class AutoMapperProfile : Profile
    {
        // mappings between model and entity objects
        public AutoMapperProfile()
        {
            CreateMap<User, UserResponse>();

            CreateMap<User, AuthenticateResponse>();

            CreateMap<RegisterRequest, User>();

            CreateMap<CreateRequest, User>();

            CreateMap<UpdateRequest, User>()
                .ForAllMembers(x => x.Condition(
                    (src, dest, prop) =>
                    {
                        // ignore null & empty string properties
                        if (prop == null) return false;
                        if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop)) return false;

                        // ignore null role
                        if (x.DestinationMember.Name == "Role" && src.Role == null) return false;

                        return true;
                    }
                ));
        }
    }
}