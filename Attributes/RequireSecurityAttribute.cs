using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Penguin.Security.Abstractions.Interfaces;
using System;
using System.Security;

namespace Penguin.Cms.Modules.Security.Attributes
{
    /// <summary>
    /// Requires a valid DI security token to access the controller action
    /// </summary>
    public sealed class RequireSecurityAttribute : ActionFilterAttribute
    {
        private const string MISSING_SECURITY_TOKEN_MESSAGE = "Security Token not present";

        /// <summary>
        /// Executes the action filter against the provided filter context
        /// </summary>
        /// <param name="context">The filter context to execture against</param>
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.HttpContext.Request.Cookies["X-Session"] != null)
            {
                try
                {
                    ISecurityToken token = context.HttpContext.RequestServices.GetService<ISecurityToken>();

                    if (token != null && token.IsValid)
                    {
                        base.OnActionExecuting(context);
                    }
                }
                catch (Exception)
                {
                    throw new SecurityException(MISSING_SECURITY_TOKEN_MESSAGE);
                }
            }
            else
            {
                throw new SecurityException(MISSING_SECURITY_TOKEN_MESSAGE);
            }
        }
    }
}