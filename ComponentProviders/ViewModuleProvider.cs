using Penguin.Cms.Abstractions.Interfaces;
using Penguin.Cms.Entities;
using Penguin.Cms.Modules.Security.SecurityProviders;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Repositories;
using Penguin.Cms.Web.Modules;
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
            PermissionableEntitySecurityProvider = permissionableEntitySecurityProvider;
            EntityPermissionsRepository = entityPermissionsRepository;
        }

        public IEnumerable<ViewModule> GetComponents(Entity Id)
        {
            EntityPermissions permissions = EntityPermissionsRepository.GetForEntity(Id);

            if (permissions is null)
            {
                permissions = new EntityPermissions()
                {
                    EntityGuid = Id.Guid,
                    Permissions = PermissionableEntitySecurityProvider.GetDefaultPermissions().ToList()
                };
            }

            MetaObject m = new MetaObject(permissions);

            m.Hydrate();

            yield return new ViewModule("~/Areas/Admin/Views/Shared/ComponentEditor.cshtml", m, "Permissions");
        }
    }
}