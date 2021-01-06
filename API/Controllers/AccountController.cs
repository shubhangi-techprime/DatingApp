using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTO;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }
        [HttpPost("register")]
        //ApiController will smartly identify from where username and password coming from for Register()
        public async Task<ActionResult<UserDto>> Register(RegisterDto registorDto)
        {
            if (await UserExists(registorDto.Username))
            {
                return BadRequest("Username is taken");
            }
            //HMACSHA5612() will use to generate Hash for password 
            using var hmac = new HMACSHA512();
            //using statment issuers when we use any above HMACSHA512 type classs this perticular methode will despose currectly,
            // using will do when any class we use it will call that methos with despose , 
            //any class that call despose menthod that class will call  desposable interface

            var user = new AddUser
            {
                UserName = registorDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registorDto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.User.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto{
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };
        }
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.User
            .SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());
            if (user == null) return Unauthorized("Invalid UserName");
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }
            return new UserDto{
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };

        }
        private async Task<bool> UserExists(string username)
        {
            return await _context.User.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}