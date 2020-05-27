using Penguin.Cms.Modules.Dynamic.Areas.Admin.Controllers;
using Penguin.Cms.Security;
using Penguin.Security.Abstractions.Constants;
using Penguin.Security.Abstractions.Interfaces;
using Penguin.Web.Security.Attributes;
using System;

namespace Penguin.Cms.Modules.Security.Areas.Admin.Controllers
{
    [RequiresRole(RoleNames.USER_MANAGER)]
    public class GroupController : ObjectManagementController<Group>
    {
        public GroupController(IServiceProvider serviceProvider, IUserSession userSession) : base(serviceProvider, userSession)
        {
        }
    }
}