using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly DataContext _context;
        public UsersController(DataContext context)
        {
            _context = context;
        }
        [HttpGet]
        public async Task<ActionResult<IEnumerable<AddUser>>> GetUsers(){
            return await _context.User.ToListAsync();
            
        }
        //api/user/2
        [HttpGet ("{id}")]
        public async Task<ActionResult<AddUser>> GetUser(int id){
            return await _context.User.FindAsync(id); 
        }
    }
}