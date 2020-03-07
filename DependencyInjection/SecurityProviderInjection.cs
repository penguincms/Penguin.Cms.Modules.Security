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
            foreach (Type t in TypeFactory.GetDerivedTypes(typeof(Entity)))
            {
                Type genericProviderType = typeof(ISecurityProvider<>).MakeGenericType(t);

                serviceRegister.Register(genericProviderType, typeof(PermissionableEntitySecurityProvider), ServiceLifetime.Scoped);
            }

            serviceRegister.Register(typeof(ISecurityProvider<Entity>), typeof(PermissionableEntitySecurityProvider), ServiceLifetime.Scoped);
        }
    }
}