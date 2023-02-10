using Microsoft.AspNetCore.Http;
using Penguin.Cms.Modules.Security.Services;
using Penguin.Web.Abstractions.Interfaces;
using System.Threading.Tasks;

namespace Penguin.Cms.Modules.Security.Middleware
{
    //http://azurecoder.net/2017/07/09/routing-middleware-custom-irouter/
    public class SecurityLayer : IPenguinMiddleware
    {
        private readonly RequestDelegate _next;

        //TODO: Learn what this is
        public SecurityLayer(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            if (context is null)
            {
                throw new System.ArgumentNullException(nameof(context));
            }

            string RequestUrl = context.Request.Path.Value.Split('?')[0];

            if (RequestUrl == SecurityService.SecurityImage || RequestUrl == SecurityService.SecurityImageTesting)
            {
                context.Request.Path = "/Security/Image";
            }

            await _next(context).ConfigureAwait(true);
        }
    }
}