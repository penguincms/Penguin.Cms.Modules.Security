using Penguin.Cms.Modules.Core.ComponentProviders;
using Penguin.Cms.Modules.Core.Navigation;
using Penguin.Cms.Security.Constants;
using Penguin.Navigation.Abstractions;
using Penguin.Security.Abstractions;
using Penguin.Security.Abstractions.Interfaces;
using System.Collections.Generic;

namespace Penguin.Cms.Modules.Security.ComponentProviders
{
    public class AdminNavigationMenuProvider : NavigationMenuProvider
    {
        public override INavigationMenu GenerateMenuTree()
        {
            return new NavigationMenu()
            {
                Name = "Admin",
                Text = "Admin",
                Children = new List<INavigationMenu>() {
                        new NavigationMenu()
                        {
                            Text = "Security",
                            Name = "SecurityAdmin",
                            Href = "/Admin/Security/Index",
                            Permissions = new List<ISecurityGroupPermission>()
                            {
                                CreatePermission(Roles.UserManager, PermissionTypes.Read),
                                CreatePermission(Roles.SysAdmin, PermissionTypes.Read | PermissionTypes.Write)
                            },
                                Children = new List<INavigationMenu>()
                                {
                                    new NavigationMenu()
                                    {
                                        Text = "Users",
                                        Name = "ListUsers",
                                        Icon = "list",
                                        Href = "/Admin/User/List",
                                        Permissions = new List<ISecurityGroupPermission>()
                                        {
                                             CreatePermission(Roles.UserManager, PermissionTypes.Read),
                                             CreatePermission(Roles.SysAdmin, PermissionTypes.Read | PermissionTypes.Write)
                                        }
                                    },
                                    new NavigationMenu()
                                    {
                                        Text = "Create User",
                                        Name = "CreateUser",
                                        Icon = "add_box",
                                        Href = "/Admin/User/Edit",
                                        Permissions = new List<ISecurityGroupPermission>()
                                        {
                                            CreatePermission(Roles.UserManager, PermissionTypes.Read),
                                            CreatePermission(Roles.SysAdmin, PermissionTypes.Read | PermissionTypes.Write)
                                        }
                                    },
                                    new NavigationMenu()
                                    {
                                        Text = "Groups",
                                        Name = "ListGroups",
                                        Icon = "list",
                                        Href = "/Admin/Group/List",
                                        Permissions = new List<ISecurityGroupPermission>()
                                        {
                                            CreatePermission(Roles.UserManager, PermissionTypes.Read),
                                            CreatePermission(Roles.SysAdmin, PermissionTypes.Read | PermissionTypes.Write)
                                        }
                                   },
                                   new NavigationMenu()
                                   {
                                       Text = "Create Group",
                                       Name = "CreateGroup",
                                       Icon = "add_box",
                                       Href = "/Admin/Group/Edit",
                                       Permissions = new List<ISecurityGroupPermission>()
                                       {
                                           CreatePermission(Roles.UserManager, PermissionTypes.Read),
                                           CreatePermission(Roles.SysAdmin, PermissionTypes.Read | PermissionTypes.Write)
                                       }
                                    },
                                    new NavigationMenu()
                                    {
                                        Text = "Roles",
                                        Name = "ListRoles",
                                        Icon = "list",
                                        Href = "/Admin/Role/List",
                                        Permissions = new List<ISecurityGroupPermission>()
                                        {
                                            CreatePermission(Roles.UserManager, PermissionTypes.Read),
                                            CreatePermission(Roles.SysAdmin, PermissionTypes.Read | PermissionTypes.Write)
                                        }
                                    },
                                    new NavigationMenu()
                                    {
                                        Text = "Create Role",
                                        Name = "CreateRole",
                                        Icon = "add_box",
                                        Href = "/Admin/Role/Edit",
                                        Permissions = new List<ISecurityGroupPermission>()
                                        {
                                            CreatePermission(Roles.UserManager, PermissionTypes.Read),
                                            CreatePermission(Roles.SysAdmin, PermissionTypes.Read | PermissionTypes.Write)
                                        }
                                    }
                                }
                                }
                            }
            };
        }
    }
}