using Penguin.Cms.Web.Security;
using Penguin.DependencyInjection.Abstractions.Enums;
using Penguin.DependencyInjection.Abstractions.Interfaces;
using Penguin.DependencyInjection.ServiceProviders;
using Penguin.Security.Abstractions.Interfaces;
using Penguin.Web.Security;
using System;
using DependencyEngine = Penguin.DependencyInjection.Engine;

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