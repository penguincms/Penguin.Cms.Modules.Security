using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Penguin.Cms.Modules.Security.Entities;
using Penguin.Cms.Modules.Security.Services;
using Penguin.DependencyInjection.Abstractions.Interfaces;
using Penguin.Security.Encryption;
using System;
using ServiceLifetime = Penguin.DependencyInjection.Abstractions.Enums.ServiceLifetime;

namespace Penguin.Cms.Modules.Security.DependencyInjection
{
    public class SecurityTokenInjection : IRegisterDependencies
    {
        public void RegisterDependencies(IServiceRegister serviceRegister)
        {
            if (serviceRegister is null)
            {
                throw new ArgumentNullException(nameof(serviceRegister));
            }

            serviceRegister.Register((IServiceProvider ServiceProvider) =>
            {
                CookieOptions option = new()
                {
                    Expires = DateTime.Now.AddDays(-10)
                };

                HttpContext context = ServiceProvider.GetService<HttpContext>();

                ISession session = context.Session;

                TeaEncryptor tea = new(session.Get(SecurityService.SECURITY_TOKEN_PASSWORD_NAME));

                string fingerPrintJson = tea.Decrypt(context.Request.Cookies["X-Session"]);

                SecurityToken securityToken = JsonConvert.DeserializeObject<SecurityToken>(fingerPrintJson);

                context.Response.Cookies.Append("X-Session", "", option);

                return securityToken;
            }, ServiceLifetime.Singleton);
        }
    }
}