using API.Data;
using System.Security.Cryptography;
using API.Entities;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using API.DTOs;
using API.Interfaces;




namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService) {
            _tokenService = tokenService;
            _context = context; 
        }

        [HttpPost("register")] //POST
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO registerDto) {
            if (await UserExists(registerDto.UserName)) return BadRequest("UserName is taken. Try again!");

            using var hmac = new HMACSHA512();
            var user = new AppUser {
                UserName = registerDto.UserName,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDTO {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            }; 
        }
        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO loginDto) {
            var user = await _context.Users.SingleOrDefaultAsync(
                x => x.UserName == loginDto.UserName);
            
            if (user == null) return Unauthorized(); 
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            for (int i = 0; i < computedHash.Length; i ++) {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("invalid password");

            }
            return new UserDTO {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            }; 
        }



        private async Task<bool> UserExists (string UserName) {
            return await _context.Users.AnyAsync(appUser => appUser.UserName == UserName.ToLower());
        }
    }
}