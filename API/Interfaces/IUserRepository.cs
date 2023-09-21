using API.DTOs;
using API.Entities;

namespace API.Interfaces
{
    public interface IUserRepository
    {
        void Update(AppUser user);

        Task<bool> SaveAllASync(); 
        Task<IEnumerable<AppUser>> GetUsersAsync(); 

        Task<AppUser> GetUserByIdAsync(int id);
        Task<AppUser> GetUserbyUsernameAsync(string username);

        Task<IEnumerable<MemberDTO>> GetMembersAsync(); 
        Task<MemberDTO> GetMemberAsync(string username); 

    }
}