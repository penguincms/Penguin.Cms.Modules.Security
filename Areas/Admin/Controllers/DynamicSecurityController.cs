using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Penguin.Cms.Entities;
using Penguin.Cms.Errors;
using Penguin.Cms.Modules.Dynamic.Areas.Admin.Controllers;
using Penguin.Cms.Modules.Security.Areas.Admin.Models;
using Penguin.Cms.Repositories.Interfaces;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Repositories;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Reflection;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Penguin.Cms.Modules.Security.Areas.Admin.Controllers
{
    public class DynamicSecurityController : DynamicController
    {
        protected EntityPermissionsRepository EntityPermissionsRepository { get; set; }

        public DynamicSecurityController(IServiceProvider serviceProvider, IFileProvider fileProvider, EntityPermissionsRepository entityPermissionsRepository, IRepository<AuditableError> errorRepository, Penguin.Messaging.Core.MessageBus? messageBus = null) : base(serviceProvider, fileProvider, errorRepository, messageBus)
        {
            EntityPermissionsRepository = entityPermissionsRepository;
        }

        [HttpPost]
        public virtual ActionResult AddPermissionsGet(AddPermisionsPageModel model)
        {
            return this.View(model);
        }

        [HttpPost]
        public virtual ActionResult AddPermissionsPost([FromBody] AddPermisionsPageModel model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            IRepository<SecurityGroup> securityGroupRepository = ServiceProvider.GetService<IRepository<SecurityGroup>>();

            foreach (Type t in TypeFactory.GetDerivedTypes(typeof(Entity)))
            {
                Type repositoryType = typeof(IEntityRepository<>).MakeGenericType(t);

                IEntityRepository permissionableEntityRepository = (IEntityRepository)ServiceProvider.GetService(repositoryType);

                using IWriteContext context = permissionableEntityRepository.WriteContext();

                IEnumerable Targets = permissionableEntityRepository.FindRange(model.Guids.Select(g => Guid.Parse(g)));

                List<SecurityGroup> Groups = securityGroupRepository.FindRange(model.SecurityGroups.Select(g => g.Guid).ToArray()).ToList();

                foreach (Entity? target in Targets)
                {
                    if (target is null)
                    {
                        continue;
                    }

                    foreach (SecurityGroup group in Groups)
                    {
                        EntityPermissionsRepository.AddPermission(target, group, model.TypeToAdd);
                    }
                }
            }

            return this.Content("Permissions successfully added");
        }
    }
}