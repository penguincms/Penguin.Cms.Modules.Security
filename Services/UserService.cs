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
using Penguin.Messaging.Core;
using Penguin.Persistence.Abstractions.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;

namespace Penguin.Cms.Modules.Security.Services
{
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    [SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters")]
    public class UserService : Penguin.Cms.Security.Services.UserService
    {
        protected IProvideConfigurations ConfigurationService { get; set; }

        protected MessageBus? MessageBus { get; set; }

        protected IRepository<Role> RoleRepository { get; set; }

        protected UserSession UserSession { get; set; }

        private class LoginModel
        {
            public string Domain { get; set; }

            public Validation DomainValidation { get; set; }

            public bool InDatabase { get; set; }

            public bool IsValidated => this.OwaValidation.Succeeded || this.DomainValidation.Succeeded || this.LocalValidation.Succeeded;

            public Validation LocalValidation { get; set; }

            public string Login { get; set; }

            public string OWAEmail
            {
                get
                {
                    if (string.IsNullOrWhiteSpace(this.Domain) && !this.Login.Contains("@", StringComparison.OrdinalIgnoreCase))
                    {
                        return string.Empty;
                    }
                    else if (!this.Login.Contains("@", StringComparison.OrdinalIgnoreCase))
                    {
                        //TODO: Make this better;
                        return $"{this.Login}@{this.Domain}.com";
                    }
                    else
                    {
                        return this.Login;
                    }
                }
            }

            public Validation OwaValidation { get; set; }

            public string Password { get; set; }

            public bool RequiresSave { get; set; }

            public User? ThisUser { get; set; }

            public LoginModel(string login, string password, string domain = "")
            {
                this.Login = login;
                this.Password = password;
                this.Domain = domain;

                this.OwaValidation = new Validation();
                this.DomainValidation = new Validation();
                this.LocalValidation = new Validation();
            }
        }

        private class Validation
        {
            public bool Attempted { get; set; }
            public bool Succeeded { get; set; }
            public bool Try { get; set; }
        }

        public UserService(UserSession userSession, UserRepository userRepository, IRepository<Role> roleRepository, IProvideConfigurations configurationService, IRepository<AuthenticationToken> authenticationTokenRepository, ISendTemplates emailTemplateRepository = null, MessageBus? messageBus = null) : base(userRepository, emailTemplateRepository, authenticationTokenRepository)
        {
            this.UserSession = userSession;
            this.UserRepository = userRepository;
            this.RoleRepository = roleRepository;
            this.ConfigurationService = configurationService;
            this.MessageBus = messageBus;
        }

        public User? Login(AuthenticationToken authenticationToken)
        {
            User tokenUser = this.GetByAuthenticationToken(authenticationToken);

            if (tokenUser != null)
            {
                this.UserSession.LoggedInUser = tokenUser;
            }

            return tokenUser;
        }

        public User? Login(string Login, string Password)
        {
            User? toReturn = null;

            StaticLogger.Log($"{Login}: Getting Domain Name");
            LoginModel loginModel = new LoginModel(Login, Password, this.ConfigurationService.GetConfiguration(ConfigurationNames.DOMAIN_NAME));

            StaticLogger.Log($"{Login}: Checking Database...");
            if (!this.UserRepository.Where(u => u.ExternalId == Login).Any())
            {
                StaticLogger.Log($"{Login}: Does not exist in database");
                loginModel.InDatabase = false;

                StaticLogger.Log($"{Login}: Checking for automatic user registration");
                if (this.ConfigurationService.GetBool(ConfigurationNames.AUTOMATIC_USER_REGISTRATION))
                {
                    loginModel.RequiresSave = true;
                }
            }
            else
            {
                StaticLogger.Log($"{Login}: Exists in database");
                loginModel.ThisUser = this.UserRepository.Find(loginModel.Login);
                loginModel.InDatabase = true;
            }

            if (string.Equals(loginModel.Login, Users.Admin.Login, StringComparison.InvariantCultureIgnoreCase))
            {
                loginModel.LocalValidation.Try = true;
                loginModel.DomainValidation.Try = false;
                loginModel.OwaValidation.Try = false;
            }
            else
            {
                StaticLogger.Log($"{Login}: Checking login providers...");
                loginModel.OwaValidation.Try = this.ConfigurationService.GetBool(ConfigurationNames.OWA_LOGIN);
                loginModel.DomainValidation.Try = this.ConfigurationService.GetBool(ConfigurationNames.DOMAIN_LOGIN);
                loginModel.LocalValidation.Try = !this.ConfigurationService.GetBool(ConfigurationNames.DISABLE_LOCAL_LOGIN);
            }
            //The order here actually matters
            if (loginModel.LocalValidation.Try)
            {
                StaticLogger.Log($"{Login}: Trying local");
                this.LocalLogin(loginModel);
            }

            if (loginModel.OwaValidation.Try)
            {
                StaticLogger.Log($"{Login}: Trying OWA");
                OWALogin(loginModel);
            }

            if (loginModel.DomainValidation.Try)
            {
                StaticLogger.Log($"{Login}: Trying Domain");
                DomainLogin(loginModel);
            }

            if (loginModel.IsValidated)
            {
                StaticLogger.Log($"{Login}: Found valid login. Opening write context");
                using (this.UserRepository.WriteContext())
                {
                    if (loginModel.ThisUser is null)
                    {
                        loginModel.ThisUser = new User
                        {
                            Login = loginModel.Login,
                            Password = loginModel.Password
                        };
                    }

                    StaticLogger.Log($"{Login}: Updating Email");
                    UpdateEmail(loginModel);

                    StaticLogger.Log($"{Login}: Updating personal info");
                    UpdatePersonal(loginModel);

                    StaticLogger.Log($"{Login}: Updating roles");
                    this.UpdateRoles(loginModel);

                    if (loginModel.RequiresSave)
                    {
                        StaticLogger.Log($"{Login}: User requires save");
                        if (!loginModel.InDatabase)
                        {
                            if (loginModel.DomainValidation.Succeeded || loginModel.DomainValidation.Succeeded)
                            {
                                loginModel.ThisUser.Source = SecurityGroup.SecurityGroupSource.ActiveDirectory;
                            }
                            else
                            {
                                loginModel.ThisUser.Source = SecurityGroup.SecurityGroupSource.Client;
                            }
                        }

                        StaticLogger.Log($"{Login}: Saving user");
                        this.UserRepository.AddOrUpdate(loginModel.ThisUser);
                    }
                }

                StaticLogger.Log($"{Login}: Setting return value");
                toReturn = this.UserRepository.Find(Login);
            }

            if (toReturn != null)
            {
                StaticLogger.Log($"{Login}: Setting session user...");
                this.UserSession.LoggedInUser = toReturn;
            }

            return toReturn;
        }

        private static void DomainLogin(LoginModel loginModel)
        {
            loginModel.DomainValidation.Attempted = true;
            loginModel.DomainValidation.Succeeded = TestDomainCredentials(loginModel.Login, loginModel.Password);
        }

        private static string GetValidDomainAccount(LoginModel loginModel)
        {
            if (loginModel.DomainValidation.Succeeded)
            {
                return loginModel.Login;
            }
            else if (loginModel.OwaValidation.Succeeded && (loginModel.DomainValidation.Attempted && !loginModel.DomainValidation.Succeeded))
            {
                using DirectoryEntry entry = new DirectoryEntry();
                // get a DirectorySearcher object
                using DirectorySearcher search = new DirectorySearcher(entry)
                {
                    // specify the search filter
                    Filter = "(&(objectClass=user)(mail=" + loginModel.OWAEmail + "))"
                };
                // specify which property values to return in the search
                search.PropertiesToLoad.Add("anr");   // account

                // perform the search
                SearchResult result = search.FindOne();

                if (result is null || result.Properties["anr"].Count < 1)
                {
                    return string.Empty;
                }
                else
                {
                    return result.Properties["anr"]?.ToString() ?? string.Empty;
                }
            }
            else
            {
                return string.Empty;
            }
        }

        private static void OWALogin(LoginModel loginModel)
        {
            loginModel.OwaValidation.Attempted = true;
            loginModel.OwaValidation.Succeeded = TestOWACredentials(loginModel.OWAEmail, loginModel.Password);
        }

        private static bool TestDomainCredentials(string UserName, string Password)
        {
            try
            {
                using PrincipalContext context = new PrincipalContext(ContextType.Domain);
                if (context.ValidateCredentials(UserName, Password))
                {
                    return true;
                }
                else
                {
                    return false;
                }
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
                OWAValidator auth = new OWAValidator();

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
                if (loginModel.ThisUser.Email != loginModel.OWAEmail)
                {
                    loginModel.RequiresSave = true;
                    loginModel.ThisUser.Email = loginModel.OWAEmail;
                }
            }
            else if (loginModel.DomainValidation.Succeeded)
            {
                using DirectoryEntry entry = new DirectoryEntry();
                // get a DirectorySearcher object
                using DirectorySearcher search = new DirectorySearcher(entry)
                {
                    // specify the search filter
                    Filter = "(&(objectClass=user)(anr=" + loginModel.Login + "))"
                };
                // specify which property values to return in the search
                search.PropertiesToLoad.Add("mail");        // smtp mail address

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
                    using DirectoryEntry entry = new DirectoryEntry();
                    // get a DirectorySearcher object
                    using DirectorySearcher search = new DirectorySearcher(entry)
                    {
                        // specify the search filter
                        Filter = "(&(objectClass=user)(anr=" + DomainLogin + "))"
                    };
                    // specify which property values to return in the search
                    search.PropertiesToLoad.Add("givenName");   // first name
                    search.PropertiesToLoad.Add("sn");          // last name

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
            loginModel.LocalValidation.Succeeded = this.UserRepository.Where(u => u.Login == loginModel.Login && u.Password == loginModel.Password) != null;
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
                using PrincipalContext ctx = new PrincipalContext(ContextType.Domain);
                // find a user
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, DomainLogin);

                if (user != null)
                {
                    List<Role> newRoles = new List<Role>();
                    // get the authorization groups - those are the "roles"
                    PrincipalSearchResult<Principal> groups = user.GetAuthorizationGroups();

                    foreach (Principal principal in groups)
                    {
                        newRoles.Add(this.RoleRepository.CreateIfNotExists(principal.Name, principal.Description, SecurityGroup.SecurityGroupSource.ActiveDirectory));
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