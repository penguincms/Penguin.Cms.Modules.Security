using Penguin.DependencyInjection.Abstractions.Interfaces;
using System;

namespace Penguin.Cms.Modules.Security.Services
{
    public class SecurityService : ISelfRegistering
    {
        public const int DUMMY_FILE_LENGTH = 178000;
        public const string IMAGE_ROOT = "/Images/Client/";
        public const int PASSWORD_LENGTH = 16;
        public const string SECURITY_TOKEN_NAME = "SecurityToken";
        public const string SECURITY_TOKEN_PASSWORD_NAME = "SecurityTokenPassword";

        /// <summary>
        /// The file path for the generated security image
        /// </summary>
        public static string SecurityImage { get; set; } = IMAGE_ROOT + Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase) + ".png";

        /// <summary>
        /// The file path for the generated security image when in debug
        /// </summary>
        public static string SecurityImageTesting { get; set; } = IMAGE_ROOT + "Security.png";

        public SecurityService()
        {
        }

        public void RegisterDependencies()
        {
        }
    }
}