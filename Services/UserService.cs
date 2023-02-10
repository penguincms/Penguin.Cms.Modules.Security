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

namespace Penguin.Cms.Modules.Security.Services
{
    public partial class UserService : Penguin.Cms.Security.Services.UserService
    {
        protected IProvideConfigurations ConfigurationService { get; set; }

        protected MessageBus? MessageBus { get; set; }

        protected IRepository<Role> RoleRepository { get; set; }

        protected UserSession UserSession { get; set; }

        private class Validation
        {
            public bool Attempted { get; set; }
            public bool Succeeded { get; set; }
            public bool Try { get; set; }
        }

        public UserService(UserSession userSession, UserRepository userRepository, IRepository<Role> roleRepository, IProvideConfigurations configurationService, IRepository<AuthenticationToken> authenticationTokenRepository, ISendTemplates? emailTemplateRepository = null, MessageBus? messageBus = null) : base(userRepository, emailTemplateRepository, authenticationTokenRepository)
        {
            UserSession = userSession;
            UserRepository = userRepository;
            RoleRepository = roleRepository;
            ConfigurationService = configurationService;
            MessageBus = messageBus;
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

        public User? Login(string Login, string Password)
        {
            User? toReturn = null;

            StaticLogger.Log($"{Login}: Getting Domain Name");
            LoginModel loginModel = new(Login, Password, ConfigurationService.GetConfiguration(ConfigurationNames.DOMAIN_NAME));

            StaticLogger.Log($"{Login}: Checking Database...");
            if (!UserRepository.Where(u => u.ExternalId == Login).Any())
            {
                StaticLogger.Log($"{Login}: Does not exist in database");
                loginModel.InDatabase = false;

                StaticLogger.Log($"{Login}: Checking for automatic user registration");
                if (ConfigurationService.GetBool(ConfigurationNames.AUTOMATIC_USER_REGISTRATION))
                {
                    loginModel.RequiresSave = true;
                }
            }
            else
            {
                StaticLogger.Log($"{Login}: Exists in database");
                loginModel.ThisUser = UserRepository.Find(loginModel.Login);
                loginModel.InDatabase = true;
            }

            if (string.Equals(loginModel.Login, Users.Admin.Login, StringComparison.OrdinalIgnoreCase))
            {
                loginModel.LocalValidation.Try = true;
                loginModel.DomainValidation.Try = false;
                loginModel.OwaValidation.Try = false;
            }
            else
            {
                StaticLogger.Log($"{Login}: Checking login providers...");
                loginModel.OwaValidation.Try = ConfigurationService.GetBool(ConfigurationNames.OWA_LOGIN);
                loginModel.ExchangeValidation.Try = ConfigurationService.GetBool(ConfigurationNames.EXCHANGE_LOGIN);
                loginModel.DomainValidation.Try = ConfigurationService.GetBool(ConfigurationNames.DOMAIN_LOGIN);
                loginModel.LocalValidation.Try = !ConfigurationService.GetBool(ConfigurationNames.DISABLE_LOCAL_LOGIN);
            }
            //The order here actually matters
            if (loginModel.LocalValidation.Try)
            {
                StaticLogger.Log($"{Login}: Trying local");
                LocalLogin(loginModel);
            }

            if (loginModel.OwaValidation.Try)
            {
                StaticLogger.Log($"{Login}: Trying OWA");

                try
                {
                    OWALogin(loginModel);
                }
                catch (Exception ex)
                {
                    StaticLogger.Log(ex.Message);
                }
            }

            if (loginModel.DomainValidation.Try)
            {
                StaticLogger.Log($"{Login}: Trying Domain");

                try
                {
                    DomainLogin(loginModel);
                }
                catch (Exception ex)
                {
                    StaticLogger.Log(ex.Message);
                }
            }

            if (loginModel.ExchangeValidation.Try)
            {
                StaticLogger.Log($"{Login}: Trying Exchange");

                try
                {
                    ExchangeLogin(loginModel);
                }
                catch (Exception ex)
                {
                    StaticLogger.Log(ex.Message);
                }
            }

            if (loginModel.IsValidated)
            {
                StaticLogger.Log($"{Login}: Found valid login. Opening write context");
                using (UserRepository.WriteContext())
                {
                    loginModel.ThisUser ??= new User
                    {
                        Login = loginModel.Login,
                        Password = loginModel.Password
                    };

                    StaticLogger.Log($"{Login}: Updating Email");
                    UpdateEmail(loginModel);

                    StaticLogger.Log($"{Login}: Updating personal info");
                    UpdatePersonal(loginModel);

                    StaticLogger.Log($"{Login}: Updating roles");
                    UpdateRoles(loginModel);

                    if (loginModel.RequiresSave)
                    {
                        StaticLogger.Log($"{Login}: User requires save");
                        if (!loginModel.InDatabase)
                        {
                            loginModel.ThisUser.Source = loginModel.DomainValidation.Succeeded || loginModel.DomainValidation.Succeeded
                                ? SecurityGroup.SecurityGroupSource.ActiveDirectory
                                : SecurityGroup.SecurityGroupSource.Client;
                        }

                        StaticLogger.Log($"{Login}: Saving user");
                        UserRepository.AddOrUpdate(loginModel.ThisUser);
                    }
                }

                StaticLogger.Log($"{Login}: Setting return value");
                toReturn = UserRepository.Find(Login);
            }

            if (toReturn != null)
            {
                StaticLogger.Log($"{Login}: Setting session user...");
                UserSession.LoggedInUser = toReturn;
            }

            return toReturn;
        }

        public User? Login(string Login, string Password, out AuthenticationToken? token, int expirationMinutes)
        {
            User? targetUser = this.Login(Login, Password);

            if (targetUser != null)
            {
                Guid Token = Guid.NewGuid();

                using (AuthenticationTokenRepository.WriteContext())
                {
                    token = new AuthenticationToken()
                    {
                        Expiration = DateTime.Now.AddMinutes(expirationMinutes),
                        User = UserRepository.Find(targetUser._Id).Guid,
                        Guid = Token
                    };

                    AuthenticationTokenRepository.AddOrUpdate(token);
                }
            }
            else
            {
                token = null;
            }

            return targetUser;
        }

        private static void DomainLogin(LoginModel loginModel)
        {
            loginModel.DomainValidation.Attempted = true;
            loginModel.DomainValidation.Succeeded = TestDomainCredentials(loginModel.Login, loginModel.Password);
        }

        private static void ExchangeLogin(LoginModel loginModel)
        {
            loginModel.ExchangeValidation.Attempted = true;

            loginModel.ExchangeValidation.Succeeded = new ExchangeAuthenticator().Authenticate(loginModel.AuthenticationEmail, loginModel.Password).Result.IsValid;
        }

        private static string GetValidDomainAccount(LoginModel loginModel)
        {
            if (loginModel.DomainValidation.Succeeded)
            {
                return loginModel.Login;
            }
            else if (loginModel.OwaValidation.Succeeded && loginModel.DomainValidation.Attempted && !loginModel.DomainValidation.Succeeded)
            {
                using DirectoryEntry entry = new();
                // get a DirectorySearcher object
                using DirectorySearcher search = new(entry)
                {
                    // specify the search filter
                    Filter = "(&(objectClass=user)(mail=" + loginModel.AuthenticationEmail + "))"
                };
                // specify which property values to return in the search
                _ = search.PropertiesToLoad.Add("anr");   // account

                // perform the search
                SearchResult result = search.FindOne();

                return result is null || result.Properties["anr"].Count < 1 ? string.Empty : result.Properties["anr"]?.ToString() ?? string.Empty;
            }
            else
            {
                return string.Empty;
            }
        }

        private static void OWALogin(LoginModel loginModel)
        {
            loginModel.OwaValidation.Attempted = true;
            loginModel.OwaValidation.Succeeded = TestOWACredentials(loginModel.AuthenticationEmail, loginModel.Password);
        }

        private static bool TestDomainCredentials(string UserName, string Password)
        {
            try
            {
                using PrincipalContext context = new(ContextType.Domain);
                return context.ValidateCredentials(UserName, Password);
            }
            catch (Exception ex)
            {
                StaticLogger.Log(ex.Message, StaticLogger.LoggingLevel.Call);
                StaticLogger.Log(ex.StackTrace, StaticLogger.LoggingLevel.Call);
                return false;
            }
        }

        private static bool TestOWACredentials(string UserName, string Password)
        {
            try
            {
                OWAValidator auth = new();

                return auth.Validate(UserName, Password);
            }
            catch (Exception ex)
            {
                StaticLogger.Log(ex.Message, StaticLogger.LoggingLevel.Call);
                StaticLogger.Log(ex.StackTrace, StaticLogger.LoggingLevel.Call);
                return false;
            }
        }

        private static void UpdateEmail(LoginModel loginModel)
        {
            if (loginModel is null)
            {
                throw new ArgumentNullException(nameof(loginModel));
            }

            if (loginModel.ThisUser is null)
            {
                throw new NullReferenceException(nameof(loginModel));
            }

            if (loginModel.OwaValidation.Succeeded)
            {
                if (loginModel.ThisUser.Email != loginModel.AuthenticationEmail)
                {
                    loginModel.RequiresSave = true;
                    loginModel.ThisUser.Email = loginModel.AuthenticationEmail;
                }
            }
            else if (loginModel.DomainValidation.Succeeded)
            {
                using DirectoryEntry entry = new();
                // get a DirectorySearcher object
                using DirectorySearcher search = new(entry)
                {
                    // specify the search filter
                    Filter = "(&(objectClass=user)(anr=" + loginModel.Login + "))"
                };
                // specify which property values to return in the search
                _ = search.PropertiesToLoad.Add("mail");        // smtp mail address

                // perform the search
                SearchResult result = search.FindOne();

                if (result.Properties["mail"].Count > 0)
                {
                    string? newValue = result.Properties["mail"][0]?.ToString();

                    if (!string.IsNullOrWhiteSpace(newValue) && newValue != loginModel.ThisUser.LastName)
                    {
                        loginModel.RequiresSave = true;
                        loginModel.ThisUser.Email = $"{newValue}";
                    }
                }
            }
        }

        private static void UpdatePersonal(LoginModel loginModel)
        {
            if (loginModel is null)
            {
                throw new ArgumentNullException(nameof(loginModel));
            }

            if (loginModel.ThisUser is null)
            {
                throw new NullReferenceException(nameof(loginModel));
            }

            if (loginModel.DomainValidation.Succeeded || loginModel.OwaValidation.Succeeded)
            {
                string DomainLogin = GetValidDomainAccount(loginModel);

                if (!string.IsNullOrWhiteSpace(DomainLogin))
                {
                    using DirectoryEntry entry = new();
                    // get a DirectorySearcher object
                    using DirectorySearcher search = new(entry)
                    {
                        // specify the search filter
                        Filter = "(&(objectClass=user)(anr=" + DomainLogin + "))"
                    };
                    // specify which property values to return in the search
                    _ = search.PropertiesToLoad.Add("givenName");   // first name
                    _ = search.PropertiesToLoad.Add("sn");          // last name

                    // perform the search
                    SearchResult result = search.FindOne();

                    if (result.Properties["sn"].Count > 0)
                    {
                        string? newValue = result.Properties["sn"][0]?.ToString();

                        if (!string.IsNullOrWhiteSpace(newValue) && newValue != loginModel.ThisUser.LastName)
                        {
                            loginModel.RequiresSave = true;
                            loginModel.ThisUser.LastName = $"{newValue}";
                        }
                    }

                    if (result.Properties["givenName"].Count > 0)
                    {
                        string? newValue = result.Properties["givenName"][0]?.ToString();

                        if (!string.IsNullOrWhiteSpace(newValue) && newValue != loginModel.ThisUser.FirstName)
                        {
                            loginModel.RequiresSave = true;
                            loginModel.ThisUser.FirstName = $"{newValue}";
                        }
                    }
                }
            }
        }

        private void LocalLogin(LoginModel loginModel)
        {
            loginModel.LocalValidation.Attempted = true;

            string HashedPassword = loginModel.Password.ComputeSha512Hash();

            loginModel.LocalValidation.Succeeded = UserRepository.Any(u => u.ExternalId == loginModel.Login && u.HashedPassword == HashedPassword);
        }

        private void UpdateRoles(LoginModel loginModel)
        {
            if (loginModel is null)
            {
                throw new ArgumentNullException(nameof(loginModel));
            }

            if (loginModel.ThisUser is null)
            {
                throw new NullReferenceException(nameof(loginModel));
            }

            string DomainLogin = GetValidDomainAccount(loginModel);

            if (!string.IsNullOrEmpty(DomainLogin))
            {
                using PrincipalContext ctx = new(ContextType.Domain);
                // find a user
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, DomainLogin);

                if (user != null)
                {
                    List<Role> newRoles = new();
                    // get the authorization groups - those are the "roles"
                    PrincipalSearchResult<Principal> groups = user.GetAuthorizationGroups();

                    foreach (Principal principal in groups)
                    {
                        newRoles.Add(RoleRepository.CreateIfNotExists(principal.Name, principal.Description, SecurityGroup.SecurityGroupSource.ActiveDirectory));
                    }

                    if (!loginModel.ThisUser.Roles.Where(r => r.Source == SecurityGroup.SecurityGroupSource.ActiveDirectory).SequenceEqual(newRoles))
                    {
                        loginModel.RequiresSave = true;
                        loginModel.ThisUser.Roles = newRoles;
                    }
                }
            }
        }
    }
}