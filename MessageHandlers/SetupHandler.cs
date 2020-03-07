using Penguin.Cms.Core.Services;
using Penguin.Cms.Entities;
using Penguin.Cms.Modules.Security.SecurityProviders;
using Penguin.Cms.Repositories.Interfaces;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Constants;
using Penguin.Cms.Security.Extensions;
using Penguin.Cms.Security.Repositories;
using Penguin.Messaging.Abstractions.Interfaces;
using Penguin.Messaging.Application.Messages;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Reflection;
using Penguin.Security.Abstractions.Constants;
using Penguin.Security.Abstractions.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Penguin.Cms.Modules.Security.MessageHandlers
{
    public class SetupHandler : IMessageHandler<Setup<SecurityGroup>>
    {
        protected ComponentService ComponentService { get; set; }
        protected IEntityRepository<Group> GroupRepository { get; set; }
        protected IEntityRepository<Role> RoleRepository { get; set; }
        protected IRepository<SecurityGroup> SecurityGroupRepository { get; set; }
        protected PermissionableEntitySecurityProvider SecurityProvider { get; set; }
        protected UserRepository UserRepository { get; set; }

        public SetupHandler(IRepository<SecurityGroup> securityGroupRepository, PermissionableEntitySecurityProvider securityProvider, ComponentService componentService, IEntityRepository<Group> groupRepository, UserRepository userRepository, IEntityRepository<Role> roleRepository)
        {
            this.SecurityGroupRepository = securityGroupRepository;
            this.ComponentService = componentService;
            this.GroupRepository = groupRepository;
            this.RoleRepository = roleRepository;
            this.UserRepository = userRepository;
            this.SecurityProvider = securityProvider;
        }

        public void AcceptMessage(Setup<SecurityGroup> message)
        {
            using (IWriteContext context = this.RoleRepository.WriteContext())
            {
                this.RoleRepository.CreateIfNotExists(RoleNames.SysAdmin, Penguin.Cms.Security.Constants.Strings.RoleStrings.SysAdmin.Description);
            }

            using (IWriteContext context = this.RoleRepository.WriteContext())
            {
                foreach (Role u in this.GatherSecurity<Role, IRole>(typeof(Roles)))
                {
                    if (this.RoleRepository.Find(u.ExternalId) is null)
                    {
                        this.RoleRepository.Add(u);
                    }
                }

                foreach (Type t in TypeFactory.GetDerivedTypes(typeof(Entity)))
                {
                    this.RoleRepository.CreateIfNotExists(t.Name, $"Grants permissions to all entities with the name {t.Name}");
                }
            }

            using (IWriteContext context = this.GroupRepository.WriteContext())
            {
                foreach (Group g in this.GatherSecurity<Group, IGroup>(typeof(Groups)))
                {
                    if (this.GroupRepository.Find(g.ExternalId) is null)
                    {
                        this.RefreshRoles(g);

                        this.GroupRepository.AddOrUpdate(g);
                    }
                }
            }

            using (IWriteContext context = this.UserRepository.WriteContext())
            {
                foreach (User u in this.GatherSecurity<User, IUser>(typeof(Users)))
                {
                    if (this.UserRepository.Find(u.ExternalId) is null)
                    {
                        this.RefreshRoles(u);
                        this.RefreshGroups(u);

                        this.UserRepository.AddOrUpdate(u);
                    }
                }
            }
        }

        private IEnumerable<TSecurityGroup> GatherSecurity<TSecurityGroup, TInterface>(Type TSource) where TSecurityGroup : SecurityGroup, new() where TInterface : ISecurityGroup
        {
            foreach (PropertyInfo p in TSource.GetProperties())
            {
                if (p.GetValue(null) is TSecurityGroup s)
                {
                    yield return s;
                }
            }

            foreach (TInterface sec in this.ComponentService.GetComponents<TInterface>())
            {
                if (sec is TSecurityGroup s)
                {
                    yield return s;
                }
                else
                {
                    TSecurityGroup toReturn = new TSecurityGroup()
                    {
                        ExternalId = sec.ExternalId,
                        Description = sec.Description
                    };

                    List<(Group, IGroup)> loadGroups = new List<(Group, IGroup)>();

                    if (toReturn is User user && sec is IUser su)
                    {
                        foreach (IGroup groupInterface in su.Groups)
                        {
                            Group newGroup = new Group()
                            {
                                ExternalId = groupInterface.ExternalId,
                                Description = groupInterface.Description
                            };

                            user.Groups.Add(newGroup);

                            loadGroups.Add((newGroup, groupInterface));
                        }
                    }

                    if (toReturn is Group group && sec is IGroup sg)
                    {
                        loadGroups.Add((group, sg));
                    }

                    foreach ((Group groupToLoad, IGroup source) in loadGroups)
                    {
                        List<Role> Roles = new List<Role>();

                        foreach (IRole r in source.Roles)
                        {
                            Roles.Add(new Role()
                            {
                                ExternalId = r.ExternalId,
                                Description = r.Description
                            });
                        }

                        groupToLoad.Roles = Roles;
                    }

                    yield return toReturn;
                }
            }
        }

        private void RefreshGroups(IHasGroups target)
        {
            foreach (Group g in target.Groups.ToList())
            {
                if (this.GroupRepository.Find(g) is Group ng)
                {
                    (target.Groups as IList<Group>)?.Remove(g);

                    (target.Groups as IList<Group>)?.Add(ng);
                }
            }
        }

        private void RefreshRoles(IHasRoles target)
        {
            foreach (Role r in target.Roles.ToList())
            {
                if (this.RoleRepository.Find(r) is Role nr)
                {
                    (target.Roles as IList<Role>)?.Remove(r);

                    (target.Roles as IList<Role>)?.Add(nr);
                }
            }
        }
    }
}