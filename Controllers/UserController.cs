using Microsoft.AspNetCore.Mvc;
using Penguin.Cms.Modules.Security.Constants.Strings;
using Penguin.Cms.Modules.Security.Models;
using Penguin.Cms.Modules.Security.Services;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Constants;
using Penguin.Cms.Security.Repositories;
using Penguin.Cms.Web.Security;
using Penguin.Configuration.Abstractions.Extensions;
using Penguin.Configuration.Abstractions.Interfaces;
using Penguin.Debugging;
using Penguin.Messaging.Application.Messages;
using Penguin.Messaging.Core;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Security.Abstractions.Exceptions;
using Penguin.Web.Configuration.Attributes;
using Penguin.Web.Errors.Attributes;
using Penguin.Web.Security.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Penguin.Cms.Modules.Security.Controllers
{
    public partial class UserController : Controller
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public const string BAD_AUTHENTICATION_TOKEN = "BadAuthenticationToken";
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

        protected IProvideConfigurations ConfigurationService { get; set; }
        protected EmailValidationRepository EmailValidationRepository { get; set; }
        protected MessageBus? MessageBus { get; set; }
        protected UserRepository UserRepository { get; set; }
        protected UserService UserService { get; set; }
        protected UserSession UserSession { get; set; }

        public UserController(IProvideConfigurations configurationService, UserSession userSession, UserRepository userRepository, UserService userService, EmailValidationRepository emailValidationRepository, MessageBus? messageBus = null)
        {
            this.UserRepository = userRepository;
            this.EmailValidationRepository = emailValidationRepository;
            this.UserService = userService;
            this.ConfigurationService = configurationService;
            this.MessageBus = messageBus;
            this.UserSession = userSession;
        }

        public ActionResult Authenticate(Guid UserId, Guid Token, string ReturnUrl)
        {
            User? user = this.UserService.Login(new AuthenticationToken() { User = UserId, Guid = Token });

            return user == null ?
                this.View(BAD_AUTHENTICATION_TOKEN) :
                (ActionResult)this.Redirect(!string.IsNullOrWhiteSpace(ReturnUrl) ? ReturnUrl : "/");
        }

        [LoggedIn]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ChangePassword() => this.View("ChangePassword");

        [HttpPost]
        [LoggedIn]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ChangePassword(ChangePasswordModel model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (!this.ModelState.IsValid)
            {
                model.NewPassword = string.Empty;
                model.ConfirmNewPassword = string.Empty;
                return this.View(model);
            }

            using (IWriteContext context = this.UserRepository.WriteContext())
            {
                User toUpdate = this.UserRepository.Find(this.UserSession.LoggedInUser._Id);

                toUpdate.Password = model.NewPassword;
            }

            return this.View("ChangePasswordSuccess");
        }

        public ActionResult EmailValidationRequired(string Id) => this.View((object)Id);

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotLogin(string Email)
        {
            this.UserService.SendLoginInformation(Email);

            return this.View("SentLogin");
        }

        [HttpGet]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotLogin() => this.View();

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotPassword(string login)
        {
            _ = this.UserService.RequestPasswordReset(login);

            return this.View("SentPassword");
        }

        [HttpGet]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotPassword() => this.View();

        public ActionResult GenerateEmailValidation(string Id)
        {
            using (IWriteContext context = this.EmailValidationRepository.WriteContext())
            {
                this.EmailValidationRepository.GenerateToken(Guid.Parse(Id), this.GetEmailValidationLink());
            }

            return this.View();
        }

        [HandleException(typeof(NotLoggedInException))]
        public ActionResult Login(string? Url = null)
        {
            if (!this.UserRepository.Any())
            {
                if (this.MessageBus is null)
                {
                    throw new NullReferenceException("Can not send security group setup message to null messagebus");
                }

                this.MessageBus.Send(new Setup<SecurityGroup>());
            }

            Url ??= this.Request.Headers["Referer"].ToString() ?? "";

            return this.View(new LoginPageModel() { ReturnUrl = Url });
        }

        [HttpPost]
        public ActionResult Login(LoginPageModel model) //TODO: Move all of this to a UserService class
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            //We want to wait a specified amount of time for the response regardless of the results, to avoid
            //Exposing any information to the client
            StaticLogger.Log($"{model.Login}: Login attempt", StaticLogger.LoggingLevel.Call);
            DateTime startLogin = DateTime.Now;
            void WaitForRedirect()
            {
                const double LoginTime = 3000;

                double toWait = LoginTime - (DateTime.Now - startLogin).TotalMilliseconds;

                StaticLogger.Log($"{model.Login}: Waiting for {toWait}", StaticLogger.LoggingLevel.Call);
                if (toWait > 0)
                {
                    System.Threading.Thread.Sleep((int)toWait);
                }
            }

            StaticLogger.Log($"{model.Login}: Calling user service...", StaticLogger.LoggingLevel.Call);
            User? user = this.UserService.Login(model.Login, model.Password);

            if (user != null)
            {
                StaticLogger.Log($"{model.Login}: User not null", StaticLogger.LoggingLevel.Call);
                if (this.ConfigurationService.GetBool(ConfigurationNames.REQUIRE_EMAIL_VALIDATION))
                {
                    if (!this.EmailValidationRepository.IsValidated(user))
                    {
                        return this.RedirectToAction(nameof(EmailValidationRequired), new { Id = user.Guid.ToString(), area = "" });
                    }
                }

                if (!string.IsNullOrWhiteSpace(model.ReturnUrl) && model.ReturnUrl != this.Request.Path.Value)
                {
                    WaitForRedirect();
                    StaticLogger.Log($"{model.Login}: Returning to {model.ReturnUrl}", StaticLogger.LoggingLevel.Call);
                    return this.Redirect(model.ReturnUrl);
                }
                else
                {
                    WaitForRedirect();
                    StaticLogger.Log($"{model.Login}: Returning Home", StaticLogger.LoggingLevel.Call);
                    return this.Redirect("/Home/Index");
                }
            }
            else
            {
                StaticLogger.Log($"{model.Login}: User is null", StaticLogger.LoggingLevel.Call);
                this.ModelState.AddModelError(string.Empty, "Invalid Login or Password" + System.Environment.NewLine);
                WaitForRedirect();
                return this.View(model);
            }
        }

        public IActionResult LoginHelp() => this.View();

        [LoggedIn]
        public ActionResult LogOut()
        {
            this.UserSession.LoggedInUser = Users.Guest;

            return this.Redirect("/");
        }

        [RequiresConfiguration(ConfigurationNames.MANUAL_USER_REGISTRATION, true)]
        public ActionResult Register() => this.UserSession.IsLoggedIn ? this.RedirectToAction("Index", "Home", null) : (ActionResult)this.View();

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.MANUAL_USER_REGISTRATION, true)]
        public ActionResult Register(RegistrationPageModel model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            System.Threading.Thread.Sleep(1000);

            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            if (this.UserRepository.GetByLogin(model.Login) != null)
            {
                this.ModelState.AddModelError(string.Empty, "Username is already taken");
                return this.View(model);
            }

            if (!this.ConfigurationService.GetBool(ConfigurationNames.ALLOW_DUPLICATE_EMAIL) && this.UserRepository.GetByEmail(model.Email) != null)
            {
                this.ModelState.AddModelError(string.Empty, "Email is already taken");
                return this.View(model);
            }

            bool EmailValidationRequired = this.ConfigurationService.GetBool(ConfigurationNames.REQUIRE_EMAIL_VALIDATION);
            User newUser;

            using (IWriteContext context = this.UserRepository.WriteContext())
            {
                newUser = new User()
                {
                    Login = model.Login,
                    Password = model.Password,
                    Email = model.Email
                };

                this.UserRepository.AddOrUpdate(newUser);

                if (EmailValidationRequired)
                {
                    this.EmailValidationRepository.GenerateToken(newUser.Guid, this.GetEmailValidationLink());
                }
            }

            if (!EmailValidationRequired)
            {
                this.ViewBag.Messages = new List<string>()
            {
                "Registration successful. You can now log in with your new account"
            };

                return this.View("Login");
            }
            else
            {
                return this.RedirectToAction(nameof(EmailValidationRequired), new { Id = newUser.Guid.ToString(), area = "" });
            }
        }

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ResetPassword(string login)
        {
            _ = this.UserService.RequestPasswordReset(login);

            return this.View();
        }

        [HttpGet]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ResetPassword(Guid UserId, Guid Token)
        {
            User? user = this.UserService.Login(new AuthenticationToken() { User = UserId, Guid = Token });

            return user == null ? this.View(BAD_AUTHENTICATION_TOKEN) : (ActionResult)this.Redirect("ChangePassword");
        }

        public ActionResult ValidateEmail(string Id)
        {
            if (this.EmailValidationRepository.IsTokenExpired(Guid.Parse(Id)))
            {
                return this.View("ValidationTokenExpired");
            }

            using (IWriteContext context = this.EmailValidationRepository.WriteContext())
            {
                this.EmailValidationRepository.ValidateToken(Guid.Parse(Id));
            }

            return this.View();
        }

        private string GetEmailValidationLink() => $"{new Uri(this.Request.Path).Scheme}://{new Uri(this.Request.Path).Authority}{this.Url.Content("~")}/User/{nameof(ValidateEmail)}/{{0}}";
    }
}