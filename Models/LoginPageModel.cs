namespace Penguin.Cms.Modules.Security.Models
{
    public class LoginPageModel
    {
        public string Login { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string ReturnUrl { get; set; } = string.Empty;
    }
}