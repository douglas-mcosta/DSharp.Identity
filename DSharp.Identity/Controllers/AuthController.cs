using DSharp.Identity.Data;
using DSharp.Identity.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace DSharp.Identity.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IdentityContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly AppSettings _appSettings;

        public AuthController(UserManager<IdentityUser> userManager,
                                SignInManager<IdentityUser> signInManager,
                                RoleManager<IdentityRole> roleManager,
                                IOptions<AppSettings> appSettings,
                                IdentityContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _appSettings = appSettings.Value;
            _context = context;
        }

        [HttpPost("Register")]
        public async Task<ActionResult> Register(RegisterUserViewModel registerUserViewModel)
        {
            if (!ModelState.IsValid) return BadRequest(registerUserViewModel);
            var user = new IdentityUser
            {
                Email = registerUserViewModel.Email,
                EmailConfirmed = true,
                UserName = registerUserViewModel.Email
            };

            var hasUserWithEmail = await _userManager.FindByEmailAsync(registerUserViewModel.Email) != null;
            if (hasUserWithEmail)
            {
                return BadRequest("Já existe um usuário com esse email cadastrado");
            }

            var result = await _userManager.CreateAsync(user, registerUserViewModel.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                return Ok(await GerarJwt(registerUserViewModel.Email));
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("Login")]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {

            if (!ModelState.IsValid) return BadRequest();

            var result = await _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, false, true);
            if (result.Succeeded)
                return Ok(await GerarJwt(loginViewModel.Email));
            if (result.IsLockedOut)
            {
                return BadRequest("Usuário bloqueado.Tente novamente mais tarde.");
            }
            return BadRequest("Usuário ou senha invalida.");
        }

        private async Task<TokenResponseViewModel> GerarJwt(string cpf)
        {
            var user = await _userManager.FindByNameAsync(cpf);
            var claims = await _userManager.GetClaimsAsync(user);

            var identityClaims = await GetClaimsUser(user, claims);
            var encodedToken = WriteToken(identityClaims);

            return TokenReponse(encodedToken, user, claims);
        }

        private async Task<ClaimsIdentity> GetClaimsUser(IdentityUser user, ICollection<Claim> claims)
        {

            //Pegando role do usuário
            var roles = await _userManager.GetRolesAsync(user);
            var roleId = _context.Roles.FirstOrDefault(x => roles.Contains(x.Name))?.Id;
            //Pegando todos os claims dessa role
            var roleClaims = _context.RoleClaims.Where(x => x.RoleId == roleId).ToList();
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

            foreach (var userRole in roles)
            {
                claims.Add(new Claim("role", userRole));
            }
            var teste = new List<Guid>();
            foreach (var roleClaim in roleClaims)
            {
                claims.Add(new Claim(roleClaim.ClaimType, roleClaim.ClaimValue));
            }

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            return identityClaims;

        }

        private string WriteToken(ClaimsIdentity identityClaims)
        {

            //Para manipular o token
            var tokenHandle = new JwtSecurityTokenHandler();
            //Key
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            //Gerar o token
            var token = tokenHandle.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _appSettings.Issuer,
                Audience = _appSettings.Audience,
                Subject = identityClaims,
                Expires = DateTime.UtcNow.AddHours(_appSettings.ExpirationInHours),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            });
            //Escrever o token. Serializar no padrão da web
            var encodedToken = tokenHandle.WriteToken(token);
            return encodedToken;
        }

        private TokenResponseViewModel TokenReponse(string encodedToken, IdentityUser user, ICollection<Claim> claims)
        {

            var filtro = new List<string>(){
                new string("sub"),
                new string("jti"),
                new string("nbf"),
                new string("iat"),
                new string("iss"),
                new string("aud"),
                new string("email"),
            };
            return new TokenResponseViewModel
            {
                AccessToken = encodedToken,
                ExpiratioIn = TimeSpan.FromHours(_appSettings.ExpirationInHours).TotalSeconds,
                UserToken = new UserTokenViewModel
                {
                    Email = user.Email,
                    UserId = user.Id,
                    Claims = claims.Select(x => new ClaimsViewModel { Type = x.Type, Value = x.Value }).Where(x => !filtro.Contains(x.Type))
                }
            };
        }

        private static long ToUnixEpochDate(DateTime date)
           => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}
