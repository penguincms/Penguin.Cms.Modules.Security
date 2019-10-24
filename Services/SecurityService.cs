using Penguin.DependencyInjection.Abstractions.Interfaces;
using System;

namespace Penguin.Cms.Modules.Security.Services
{
    public class SecurityService : ISelfRegistering
    {
        public static string SecurityImage { get; set; } = ImageRoot + Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase) + ".png";
        public static string SecurityImageTesting { get; set; } = ImageRoot + "Security.png";
        public const int DummyFileLength = 178000;
        public const string ImageRoot = "/Images/Client/";
        public const int PasswordLength = 16;
        public const string SecurityTokenName = "SecurityToken";
        public const string SecurityTokenPasswordName = "SecurityTokenPassword";

        public SecurityService()
        {
        }

        public void RegisterDependencies()
        {
        }
    }
}