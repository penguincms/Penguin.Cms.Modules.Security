using Loxifi;
using Penguin.Cms.Entities;
using Penguin.Cms.Modules.Security.SecurityProviders;
using Penguin.DependencyInjection.Abstractions.Enums;
using Penguin.DependencyInjection.Abstractions.Interfaces;
using Penguin.Reflection;
using Penguin.Security.Abstractions.Interfaces;
using System;

namespace Penguin.Cms.Modules.Security.DependencyInjection
{
    public class SecurityProviderInjection : IRegisterDependencies
    {
        public void RegisterDependencies(IServiceRegister serviceRegister)
        {
            if (serviceRegister is null)
            {
                throw new ArgumentNullException(nameof(serviceRegister));
            }

            foreach (Type t in TypeFactory.Default.GetDerivedTypes(typeof(Entity)))
            {
                Type genericProviderType = typeof(ISecurityProvider<>).MakeGenericType(t);

                serviceRegister.Register(genericProviderType, typeof(PermissionableEntitySecurityProvider), ServiceLifetime.Scoped);
            }

            serviceRegister.Register(typeof(ISecurityProvider<Entity>), typeof(PermissionableEntitySecurityProvider), ServiceLifetime.Scoped);
        }
    }
}