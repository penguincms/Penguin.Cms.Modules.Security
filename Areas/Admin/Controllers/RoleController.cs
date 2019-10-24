﻿using Penguin.Cms.Modules.Dynamic.Areas.Admin.Controllers;
using Penguin.Cms.Security;
using Penguin.Security.Abstractions.Constants;
using Penguin.Web.Security.Attributes;
using System;

namespace Penguin.Cms.Modules.Security.Areas.Admin.Controllers
{
    [RequiresRole(RoleNames.UserManager)]
    public class RoleController : ObjectManagementController<Role>
    {
        public RoleController(IServiceProvider serviceProvider) : base(serviceProvider)
        {
        }
    }
}