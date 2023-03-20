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
        public const string BAD_AUTHENTICATION_TOKEN = "BadAuthenticationToken";

        protected IProvideConfigurations ConfigurationService { get; set; }

        protected EmailValidationRepository EmailValidationRepository { get; set; }

        protected MessageBus? MessageBus { get; set; }

        protected UserRepository UserRepository { get; set; }

        protected UserService UserService { get; set; }

        protected UserSession UserSession { get; set; }

        public UserController(IProvideConfigurations configurationService, UserSession userSession, UserRepository userRepository, UserService userService, EmailValidationRepository emailValidationRepository, MessageBus? messageBus = null)
        {
            UserRepository = userRepository;
            EmailValidationRepository = emailValidationRepository;
            UserService = userService;
            ConfigurationService = configurationService;
            MessageBus = messageBus;
            UserSession = userSession;
        }

        public ActionResult Authenticate(Guid UserId, Guid Token, string ReturnUrl)
        {
            User? user = UserService.Login(new AuthenticationToken() { User = UserId, Guid = Token });

            return user == null ?
                View(BAD_AUTHENTICATION_TOKEN) :
                Redirect(!string.IsNullOrWhiteSpace(ReturnUrl) ? ReturnUrl : "/");
        }

        public ActionResult Authenticate(Guid UserId, Guid Token, Uri ReturnUrl)
        {
            throw new NotImplementedException();
        }

        [LoggedIn]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ChangePassword()
        {
            return View("ChangePassword");
        }

        [HttpPost]
        [LoggedIn]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ChangePassword(ChangePasswordModel model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (!ModelState.IsValid)
            {
                model.NewPassword = string.Empty;
                model.ConfirmNewPassword = string.Empty;
                return View(model);
            }

            using (IWriteContext context = UserRepository.WriteContext())
            {
                User toUpdate = UserRepository.Find(UserSession.LoggedInUser._Id);

                toUpdate.Password = model.NewPassword;
            }

            return View("ChangePasswordSuccess");
        }

        public ActionResult EmailValidationRequired(string Id)
        {
            return View((object)Id);
        }

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotLogin(string Email)
        {
            UserService.SendLoginInformation(Email);

            return View("SentLogin");
        }

        [HttpGet]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotLogin()
        {
            return View();
        }

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotPassword(string login)
        {
            _ = UserService.RequestPasswordReset(login);

            return View("SentPassword");
        }

        [HttpGet]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        public ActionResult GenerateEmailValidation(string Id)
        {
            using (IWriteContext context = EmailValidationRepository.WriteContext())
            {
                EmailValidationRepository.GenerateToken(Guid.Parse(Id), GetEmailValidationLink());
            }

            return View();
        }

        [HandleException(typeof(NotLoggedInException))]
        public ActionResult Login(string? Url = null)
        {
            if (!UserRepository.Any())
            {
                if (MessageBus is null)
                {
                    throw new NullReferenceException("Can not send security group setup message to null messagebus");
                }

                MessageBus.Send(new Setup<SecurityGroup>());
            }

            Url ??= Request.Headers["Referer"].ToString() ?? "";

            return View(new LoginPageModel() { ReturnUrl = Url });
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
            User? user = UserService.Login(model.Login, model.Password);

            if (user != null)
            {
                StaticLogger.Log($"{model.Login}: User not null", StaticLogger.LoggingLevel.Call);
                if (ConfigurationService.GetBool(ConfigurationNames.REQUIRE_EMAIL_VALIDATION))
                {
                    if (!EmailValidationRepository.IsValidated(user))
                    {
                        return RedirectToAction(nameof(EmailValidationRequired), new { Id = user.Guid.ToString(), area = "" });
                    }
                }

                if (!string.IsNullOrWhiteSpace(model.ReturnUrl) && model.ReturnUrl != Request.Path.Value)
                {
                    WaitForRedirect();
                    StaticLogger.Log($"{model.Login}: Returning to {model.ReturnUrl}", StaticLogger.LoggingLevel.Call);
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    WaitForRedirect();
                    StaticLogger.Log($"{model.Login}: Returning Home", StaticLogger.LoggingLevel.Call);
                    return Redirect("/Home/Index");
                }
            }
            else
            {
                StaticLogger.Log($"{model.Login}: User is null", StaticLogger.LoggingLevel.Call);
                ModelState.AddModelError(string.Empty, "Invalid Login or Password" + System.Environment.NewLine);
                WaitForRedirect();
                return View(model);
            }
        }

        public ActionResult Login(Uri Url)
        {
            throw new NotImplementedException();
        }

        public IActionResult LoginHelp()
        {
            return View();
        }

        [LoggedIn]
        public ActionResult LogOut()
        {
            UserSession.LoggedInUser = Users.Guest;

            return Redirect("/");
        }

        [RequiresConfiguration(ConfigurationNames.MANUAL_USER_REGISTRATION, true)]
        public ActionResult Register()
        {
            return UserSession.IsLoggedIn ? RedirectToAction("Index", "Home", null) : View();
        }

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.MANUAL_USER_REGISTRATION, true)]
        public ActionResult Register(RegistrationPageModel model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            System.Threading.Thread.Sleep(1000);

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (UserRepository.GetByLogin(model.Login) != null)
            {
                ModelState.AddModelError(string.Empty, "Username is already taken");
                return View(model);
            }

            if (!ConfigurationService.GetBool(ConfigurationNames.ALLOW_DUPLICATE_EMAIL) && UserRepository.GetByEmail(model.Email) != null)
            {
                ModelState.AddModelError(string.Empty, "Email is already taken");
                return View(model);
            }

            bool EmailValidationRequired = ConfigurationService.GetBool(ConfigurationNames.REQUIRE_EMAIL_VALIDATION);
            User newUser;

            using (IWriteContext context = UserRepository.WriteContext())
            {
                newUser = new User()
                {
                    Login = model.Login,
                    Password = model.Password,
                    Email = model.Email
                };

                UserRepository.AddOrUpdate(newUser);

                if (EmailValidationRequired)
                {
                    EmailValidationRepository.GenerateToken(newUser.Guid, GetEmailValidationLink());
                }
            }

            if (!EmailValidationRequired)
            {
                ViewBag.Messages = new List<string>()
            {
                "Registration successful. You can now log in with your new account"
            };

                return View("Login");
            }
            else
            {
                return RedirectToAction(nameof(EmailValidationRequired), new { Id = newUser.Guid.ToString(), area = "" });
            }
        }

        [HttpPost]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ResetPassword(string login)
        {
            _ = UserService.RequestPasswordReset(login);

            return View();
        }

        [HttpGet]
        [RequiresConfiguration(ConfigurationNames.DISABLE_LOCAL_LOGIN, false)]
        public ActionResult ResetPassword(Guid UserId, Guid Token)
        {
            User? user = UserService.Login(new AuthenticationToken() { User = UserId, Guid = Token });

            return user == null ? View(BAD_AUTHENTICATION_TOKEN) : Redirect("ChangePassword");
        }

        public ActionResult ValidateEmail(string Id)
        {
            if (EmailValidationRepository.IsTokenExpired(Guid.Parse(Id)))
            {
                return View("ValidationTokenExpired");
            }

            using (IWriteContext context = EmailValidationRepository.WriteContext())
            {
                _ = EmailValidationRepository.ValidateToken(Guid.Parse(Id));
            }

            return View();
        }

        private string GetEmailValidationLink()
        {
            return $"{new Uri(Request.Path).Scheme}://{new Uri(Request.Path).Authority}{Url.Content("~")}/User/{nameof(ValidateEmail)}/{{0}}";
        }
    }
}