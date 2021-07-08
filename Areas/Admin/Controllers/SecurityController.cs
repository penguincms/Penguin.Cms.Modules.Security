using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Penguin.Cms.Modules.Admin.Areas.Admin.Controllers;
using Penguin.Cms.Modules.Core.Models;
using Penguin.Cms.Modules.Dynamic.Attributes;
using Penguin.Cms.Modules.Dynamic.Constants.Strings;
using Penguin.Cms.Security;
using Penguin.Persistence.Abstractions.Attributes.Control;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Reflection.Serialization.Abstractions.Interfaces;
using Penguin.Reflection.Serialization.Abstractions.Wrappers;
using Penguin.Reflection.Serialization.Extensions;
using Penguin.Security.Abstractions.Constants;
using Penguin.Security.Abstractions.Interfaces;
using Penguin.Web.Security.Attributes;
using System;
using System.Collections.Generic;

namespace Penguin.Cms.Modules.Security.Areas.Admin.Controllers
{
    public class SecurityController : AdminController
    {
        public SecurityController(IServiceProvider serviceProvider, IUserSession userSession) : base(serviceProvider, userSession)
        {
        }

        [RequiresRole(RoleNames.USER_MANAGER)]
        public ActionResult SecurityGroupPermissionSelector(IMetaObject model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            IRepository<SecurityGroup> securityGroupRepository = this.ServiceProvider.GetService<IRepository<SecurityGroup>>();
            List<SecurityGroup> ToDisplay = new List<SecurityGroup>();

            foreach (IMetaObject o in model.CollectionItems)
            {
                SecurityGroup securityGroup = securityGroupRepository.Find(o.GetValue<System.Guid>(nameof(SecurityGroup.Guid)));

                if (securityGroup != null)
                {
                    ToDisplay.Add(securityGroup);
                }
            }

            model = new MetaObjectHolder(ToDisplay);

            InputListPageModel pageModel = new InputListPageModel(model, nameof(SecurityGroup.ExternalId), nameof(SecurityGroup.Guid), Urls.SEARCH);

            return this.View("InputList", pageModel);
        }

        [RequiresRole(RoleNames.USER_MANAGER)]
        [DynamicHandler(DisplayContexts.Edit, typeof(List<Group>), typeof(List<Role>))]
        public ActionResult SecurityGroupSelector(IMetaObject model)
        {
            InputListPageModel pageModel = new InputListPageModel(model, nameof(SecurityGroup.ExternalId), nameof(SecurityGroup.Guid), Urls.SEARCH);

            return this.View("InputList", pageModel);
        }
    }
}