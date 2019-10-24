using Penguin.Cms.Entities;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Extensions;
using Penguin.Cms.Security.Constants;
using Penguin.Cms.Security.Repositories;
using Penguin.DependencyInjection.Abstractions.Interfaces;
using Penguin.Messaging.Abstractions.Interfaces;
using Penguin.Messaging.Persistence.Interfaces;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Security.Abstractions;
using Penguin.Security.Abstractions.Constants;
using Penguin.Security.Abstractions.Interfaces;
using Penguin.Security.Abstractions.Providers;
using System;
using System.Collections.Generic;
using Penguin.Cms.Web.Security;
using Penguin.Cms.Repositories.Interfaces;

namespace Penguin.Cms.Modules.Security.SecurityProviders
{
    public class PermissionableEntitySecurityProvider : ISecurityProvider<Entity>, IMessageHandler<IUpdating<Entity>>, ISelfRegistering
    {
        protected EntityPermissionsRepository EntityPermissionsRepository { get; set; }
        protected IRepository<Role> RoleRepository { get; set; }
        protected IEntityRepository<SecurityGroup> SecurityGroupRepository { get; set; }
        protected UserRepository UserRepository { get; set; }
        protected IUserSession UserSession { get; set; }

        public PermissionableEntitySecurityProvider(IUserSession userSession, IEntityRepository<SecurityGroup> securityGroupRepository, EntityPermissionsRepository entityPermissionsRepository, IRepository<Role> roleRepository, UserRepository userRepository)
        {
            EntityPermissionsRepository = entityPermissionsRepository;
            UserSession = userSession;
            RoleRepository = roleRepository;
            UserRepository = userRepository;
            SecurityGroupRepository = securityGroupRepository;
        }

        public void AcceptMessage(IUpdating<Entity> update)
        {
            if (EntityPermissionsRepository.GetForEntity(update.Target) is null)
            {
                this.SetDefaultPermissions(update.Target);
            }
        }

        public void AddPermissions(Entity entity, PermissionTypes permissionTypes, ISecurityGroup source = null)
        {
            EntityPermissionsRepository.AddPermission(entity, SecurityGroupRepository.Find(source?.Guid ?? UserSession.LoggedInUser.Guid), permissionTypes);
        }

        public void AddPermissions(Entity entity, PermissionTypes permissionTypes, Guid source)
        {
            this.AddPermissions(entity, permissionTypes, SecurityGroupRepository.Find(source));
        }

        public bool CheckAccess(Entity entity, PermissionTypes permissionTypes = PermissionTypes.Read)
        {
            if (entity is null)
            {
                return false;
            }

            return new ObjectSecurityProvider(UserSession).CheckAccess(entity) ||
             EntityPermissionsRepository.AllowsAccessType(entity, this.UserSession.LoggedInUser, permissionTypes);
        }

        public void ClonePermissions(Entity source, Entity destination)
        {
            foreach (SecurityGroupPermission sg in EntityPermissionsRepository.GetForEntity(source).Permissions)
            {
                this.AddPermissions(destination, sg.Type, sg.SecurityGroup);
            }
        }

        public IEnumerable<SecurityGroupPermission> GetDefaultPermissions()
        {
            yield return new SecurityGroupPermission()
            {
                SecurityGroup = this.RoleRepository.Find(RoleNames.SysAdmin),
                Type = PermissionTypes.Full
            };

            if (this.UserSession.IsLoggedIn)
            {
                yield return new SecurityGroupPermission()
                {
                    SecurityGroup = UserRepository.Find(this.UserSession.LoggedInUser.ExternalId),
                    Type = PermissionTypes.Full
                };
            }
        }

        public void SetDefaultPermissions(params Entity[] o)
        {
            foreach (Entity entity in o)
            {
                foreach (SecurityGroupPermission sg in GetDefaultPermissions())
                {
                    if (sg.SecurityGroup is null)
                    {
                        continue;
                    }

                    EntityPermissionsRepository.AddPermission(entity, sg.SecurityGroup, sg.Type);
                }
            }
        }

        public void SetLoggedIn(Entity entity)
        {
            EntityPermissionsRepository.AddPermission(entity, Roles.LoggedIn, PermissionTypes.Read);
        }

        public void SetPublic(Entity entity)
        {
            EntityPermissionsRepository.AddPermission(entity, Roles.Guest, PermissionTypes.Read);
            EntityPermissionsRepository.AddPermission(entity, Roles.LoggedIn, PermissionTypes.Read);
        }
    }
}