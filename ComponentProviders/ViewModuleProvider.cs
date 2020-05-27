using Penguin.Cms.Abstractions.Interfaces;
using Penguin.Cms.Entities;
using Penguin.Cms.Modules.Security.SecurityProviders;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Repositories;
using Penguin.Cms.Web.Modules;
using Penguin.Reflection.Serialization.Abstractions.Interfaces;
using Penguin.Reflection.Serialization.Abstractions.Wrappers;
using Penguin.Reflection.Serialization.Objects;
using System.Collections.Generic;
using System.Linq;

namespace Penguin.Cms.Modules.Security.ComponentProviders
{
    public class ViewModuleProvider : IProvideComponents<ViewModule, Entity>
    {
        protected EntityPermissionsRepository EntityPermissionsRepository { get; set; }
        protected PermissionableEntitySecurityProvider PermissionableEntitySecurityProvider { get; set; }

        public ViewModuleProvider(EntityPermissionsRepository entityPermissionsRepository, PermissionableEntitySecurityProvider permissionableEntitySecurityProvider)
        {
            this.PermissionableEntitySecurityProvider = permissionableEntitySecurityProvider;
            this.EntityPermissionsRepository = entityPermissionsRepository;
        }

        public IEnumerable<ViewModule> GetComponents(Entity Id)
        {
            EntityPermissions permissions = this.EntityPermissionsRepository.GetForEntity(Id);

            if (permissions is null)
            {
                permissions = new EntityPermissions()
                {
                    EntityGuid = Id.Guid,
                    Permissions = this.PermissionableEntitySecurityProvider.GetDefaultPermissions().ToList()
                };
            }

            IMetaObject m = new MetaObjectHolder(permissions);

            yield return new ViewModule("~/Areas/Admin/Views/Shared/ComponentEditor.cshtml", m, "Permissions");
        }
    }
}