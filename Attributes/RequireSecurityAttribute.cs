using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Penguin.Security.Abstractions.Interfaces;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Security;

namespace Penguin.Cms.Modules.Security.Attributes
{
    /// <summary>
    /// Requires a valid DI security token to access the controller action
    /// </summary>
    public class RequireSecurityAttribute : ActionFilterAttribute
    {
        private const string MISSING_SECURITY_TOKEN_MESSAGE = "Security Token not present";

        /// <summary>
        /// Executes the action filter against the provided filter context
        /// </summary>
        /// <param name="filterContext">The filter context to execture against</param>
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (filterContext is null)
            {
                throw new ArgumentNullException(nameof(filterContext));
            }

            if (filterContext.HttpContext.Request.Cookies["X-Session"] != null)
            {
                try
                {
                    ISecurityToken token = filterContext.HttpContext.RequestServices.GetService<ISecurityToken>();

                    if (token != null && token.IsValid)
                    {
                        base.OnActionExecuting(filterContext);
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