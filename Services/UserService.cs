using Penguin.Authentication.Abstractions.Interfaces;
using Penguin.Authentication.Exchange;
using Penguin.Authentication.OWA;
using Penguin.Cms.Modules.Security.Constants.Strings;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Constants;
using Penguin.Cms.Security.Extensions;
using Penguin.Cms.Security.Repositories;
using Penguin.Cms.Web.Security;
using Penguin.Configuration.Abstractions.Extensions;
using Penguin.Configuration.Abstractions.Interfaces;
using Penguin.Debugging;
using Penguin.Email.Templating.Abstractions.Interfaces;
using Penguin.Extensions.String.Security;
using Penguin.Messaging.Core;
using Penguin.Persistence.Abstractions.Interfaces;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Threading.Tasks;

namespace Penguin.Cms.Modules.Security.Services
{
    public partial class UserService : Penguin.Cms.Security.Services.UserService
    {
        private class Validation
        {
            public bool Attempted { get; set; }

            public bool Succeeded { get; set; }

            public bool Try { get; set; }
        }

        protected IProvideConfigurations ConfigurationService { get; set; }

        protected MessageBus? MessageBus { get; set; }

        protected IRepository<Role> RoleRepository { get; set; }

        protected UserSession UserSession { get; set; }

        protected IList<IAuthenticator> Authenticators { get; }

        public UserService(UserSession userSession, UserRepository userRepository, IRepository<Role> roleRepository, IProvideConfigurations configurationService, IRepository<AuthenticationToken> authenticationTokenRepository, IEnumerable<IAuthenticator> authenticators = null, ISendTemplates? emailTemplateRepository = null, MessageBus? messageBus = null) : base(userRepository, emailTemplateRepository, authenticationTokenRepository)
        {
            UserSession = userSession;
            UserRepository = userRepository;
            RoleRepository = roleRepository;
            ConfigurationService = configurationService;
            MessageBus = messageBus;
            Authenticators = authenticators.ToList();
        }

        public User? Login(AuthenticationToken authenticationToken)
        {
            User tokenUser = GetByAuthenticationToken(authenticationToken);

            if (tokenUser != null)
            {
                UserSession.LoggedInUser = tokenUser;
            }

            return tokenUser;
        }

        public async Task<User?> Login(string username, string password, string domain = null)
        {
            User? toReturn = null;

            StaticLogger.Log($"{username}: Getting Domain Name");

            domain ??= ConfigurationService.GetConfiguration(ConfigurationNames.DOMAIN_NAME);
            
            LoginModel loginModel = new(username, password, domain);

            StaticLogger.Log($"{username}: Checking Database...");
            if (!UserRepository.Where(u => u.ExternalId == username).Any())
            {
                StaticLogger.Log($"{username}: Does not exist in database");
                loginModel.InDatabase = false;

                StaticLogger.Log($"{username}: Checking for automatic user registration");
                if (ConfigurationService.GetBool(ConfigurationNames.AUTOMATIC_USER_REGISTRATION))
                {
                    loginModel.RequiresSave = true;
                }
            }
            else
            {
                StaticLogger.Log($"{username}: Exists in database");
                loginModel.ThisUser = UserRepository.Find(loginModel.Login);
                loginModel.InDatabase = true;
            }

            bool tryLocal = !ConfigurationService.GetBool(ConfigurationNames.DISABLE_LOCAL_LOGIN);
            bool tryOthers = true;

            if (string.Equals(loginModel.Login, Users.Admin.Login, StringComparison.OrdinalIgnoreCase))
            {
                tryLocal = true;
                tryOthers = false;
            }

            //The order here actually matters
            if (tryLocal)
            {
                StaticLogger.Log($"{username}: Trying local");
                LocalLogin(loginModel);
            }

            if (tryOthers) 
            {
                foreach (IAuthenticator authenticator in Authenticators)
                {
                    var result = await authenticator.Authenticate(username, password, domain);

                    loginModel.Validations.Add(new Validation()
                    {
                        Attempted = true,
                        Succeeded = result.IsValid
                    });

                    if(result.IsValid)
                    {
                        loginModel.IsExternal = true;
                    }
                }
            }

            if (loginModel.IsValidated)
            {
                StaticLogger.Log($"{username}: Found valid login. Opening write context");
                
                using (UserRepository.WriteContext())
                {
                    if (loginModel.ThisUser is null)
                    {
                        loginModel.ThisUser = new User
                        {
                            Login = loginModel.Login,
                            Password = loginModel.Password
                        };
                    } else
                    {
                        loginModel.ThisUser = UserRepository.Find(username);
                    }

                    if (loginModel.RequiresSave)
                    {
                        StaticLogger.Log($"{username}: User requires save");
                        if (!loginModel.InDatabase)
                        {
                            loginModel.ThisUser.Source = loginModel.IsExternal
                                ? SecurityGroup.SecurityGroupSource.Other
                                : SecurityGroup.SecurityGroupSource.Client;
                        }

                        StaticLogger.Log($"{username}: Saving user");
                        UserRepository.AddOrUpdate(loginModel.ThisUser);
                    }
                }

                StaticLogger.Log($"{username}: Setting return value");
                toReturn = UserRepository.Find(username);
            }

            if (toReturn != null)
            {
                StaticLogger.Log($"{username}: Setting session user...");
                UserSession.LoggedInUser = toReturn;
            }

            return toReturn;
        }

        private void LocalLogin(LoginModel loginModel)
        {
            string HashedPassword = loginModel.Password.ComputeSha512Hash();

            bool testPass = UserRepository.Any(u => u.ExternalId == loginModel.Login && u.HashedPassword == HashedPassword); ;

            loginModel.Validations.Add(new Validation()
            {
                Attempted = true,
                Succeeded = testPass
            });
        }
    }
}