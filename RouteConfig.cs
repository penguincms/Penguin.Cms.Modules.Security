using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Penguin.Web.Abstractions.Interfaces;

namespace Penguin.Cms.Modules.Security
{
    public class RouteConfig : IRouteConfig
    {
        public void RegisterRoutes(IRouteBuilder routes)
        {
            _ = routes.MapRoute(
                name: "Profile",
                template: "V/{Username?}",
                defaults: new { controller = "Profile", action = "V" }
            );
        }
    }
}