using System.ComponentModel.DataAnnotations;

namespace Penguin.Cms.Modules.Security.Models
{
    public class ChangePasswordModel
    {
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmNewPassword { get; set; } = string.Empty;

        public string NewPassword { get; set; } = string.Empty;
    }
}