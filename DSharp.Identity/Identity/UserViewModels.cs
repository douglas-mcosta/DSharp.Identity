using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace DSharp.Identity.Identity
{
    public class RegisterUserViewModel
    {

        [Required(ErrorMessage = "O campo {0} é obrigatório.")]
        [EmailAddress(ErrorMessage = "O campo {0} está no formado invalido.")]
        public string Email { get; set; }
        [Required(ErrorMessage = "O campo {0} é obrigatório.")]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter entre {2} e {1} caracteres.", MinimumLength = 6)]
        public string Password { get; set; }
        [Required(ErrorMessage = "O campo {0} é obrigatório.")]
        [Compare("Password", ErrorMessage = "As senhas não conferem.")]
        public string ConfirmPassword { get; set; }
    }
    public class UserTokenViewModel
    {
        public string UserId { get; set; }
        public string Email { get; set; }
        public IEnumerable<ClaimsViewModel> Claims { get; set; }
    }
    public class ClaimsViewModel
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }
    public class LoginViewModel
    {
        [Required(ErrorMessage = "O campo {0} é obrigatório.")]
        [EmailAddress(ErrorMessage = "O campo {0} está no formado invalido.")]
        public string Email { get; set; }
        [Required(ErrorMessage = "O campo {0} é obrigatório.")]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter entre {2} e {1} caracteres.", MinimumLength = 6)]
        public string Password { get; set; }
    }
    public class TokenResponseViewModel
    {
        public string AccessToken { get; set; }
        public double ExpiratioIn { get; set; }
        public UserTokenViewModel UserToken { get; set; }
    }

}
