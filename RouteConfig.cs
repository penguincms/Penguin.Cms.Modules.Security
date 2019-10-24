using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Penguin.Web.Abstractions.Interfaces;

namespace Framework.Client
{
    public class RouteConfig : IRouteConfig
    {
        public void RegisterRoutes(IRouteBuilder routes)
        {
            routes.MapRoute(
                name: "Profile",
                template: "V/{Username?}",
                defaults: new { controller = "Profile", action = "V" }
            );
        }
    }
}