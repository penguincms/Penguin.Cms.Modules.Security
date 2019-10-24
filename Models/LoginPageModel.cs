using System.Diagnostics.CodeAnalysis;

namespace Penguin.Cms.Modules.Security.Models
{
    [SuppressMessage("Design", "CA1056:Uri properties should not be strings")]
    public class LoginPageModel
    {
        public string Login { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string ReturnUrl { get; set; } = string.Empty;
    }
}