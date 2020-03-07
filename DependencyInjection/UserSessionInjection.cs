using Penguin.Cms.Web.Security;
using Penguin.DependencyInjection.Abstractions.Enums;
using Penguin.DependencyInjection.Abstractions.Interfaces;
using Penguin.Security.Abstractions.Interfaces;

namespace Penguin.Cms.Modules.Security.DependencyInjection
{
    public class UserSessionInjection : IRegisterDependencies
    {
        public void RegisterDependencies(IServiceRegister serviceRegister)
        {
            serviceRegister.Register(typeof(IUserSession), typeof(UserSession), ServiceLifetime.Scoped);
            serviceRegister.Register(typeof(UserSession), typeof(UserSession), ServiceLifetime.Scoped);
        }
    }
}