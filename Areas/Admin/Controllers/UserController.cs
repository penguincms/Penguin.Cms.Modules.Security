using Microsoft.AspNetCore.Mvc;
using Penguin.Cms.Modules.Dynamic.Areas.Admin.Controllers;
using Penguin.Cms.Modules.Dynamic.Attributes;
using Penguin.Cms.Modules.Security.Constants.Strings;
using Penguin.Cms.Modules.Security.Services;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Repositories;
using Penguin.Cms.Web.Extensions;
using Penguin.Persistence.Abstractions.Attributes.Control;
using Penguin.Reflection.Serialization.Abstractions.Interfaces;
using Penguin.Security.Abstractions.Constants;
using Penguin.Security.Abstractions.Interfaces;
using Penguin.Web.Configuration.Attributes;
using Penguin.Web.Security.Attributes;
using System;

namespace Penguin.Cms.Modules.Security.Areas.Admin.Controllers
{
    [RequiresRole(RoleNames.USER_MANAGER)]
    public class UserController : ObjectManagementController<User>
    {
        protected UserRepository UserRepository { get; set; }

        protected UserService UserService { get; set; }

        public UserController(UserService userService, UserRepository userRepository, IServiceProvider serviceProvider, IUserSession userSession) : base(serviceProvider, userSession)
        {
            this.UserRepository = userRepository;
            this.UserService = userService;
        }

        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ResetPassword(string login)
        {
            AuthenticationToken Token = this.UserService.RequestPasswordReset(login);

            return this.View(Token);
        }

        [DynamicPropertyHandler(DisplayContexts.Edit, typeof(User), nameof(Penguin.Cms.Security.User.Password))]
        public ActionResult ResetPasswordButton(IMetaObject model)
        {
            return model is null
                ? throw new ArgumentNullException(nameof(model))
                : this.View(model.Parent.FromDatabase<User>(this.ServiceProvider));
        }
    }
}