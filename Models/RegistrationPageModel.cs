using System.ComponentModel.DataAnnotations;

namespace Penguin.Cms.Modules.Security.Models
{
    public class RegistrationPageModel
    {
        [Required]
        [Compare("Email", ErrorMessage = "Confirm Email does not match Email")]
        public string ConfirmEmail { get; set; } = string.Empty;

        [Required]
        [MinLength(6)]
        [Compare("Password", ErrorMessage = "Confirm Password does not match Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(4)]
        [RegularExpression(@"^[a-zA-Z0-9]+$", ErrorMessage = "Login must be letters and numbers only")]
        public string Login { get; set; } = string.Empty;

        [Required]
        [MinLength(6)]
        public string Password { get; set; } = string.Empty;
    }
}