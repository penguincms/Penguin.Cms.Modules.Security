using Microsoft.AspNetCore.Mvc;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Repositories;
using Penguin.Cms.Security.Extensions;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Web.Security;
using Penguin.Web.Security.Attributes;
using System;
using System.Diagnostics.CodeAnalysis;
using Penguin.Cms.Web.Security;

namespace Penguin.Cms.Modules.Security.Controllers
{
    [SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters")]
    public class ProfileController : Controller
    {
        public IRepository<UserProfile> ProfileRepository { get; set; }

        protected UserRepository UserRepository { get; set; }

        protected UserSession UserSession { get; set; }

        public ProfileController(IRepository<UserProfile> profileRepository, UserRepository userRepository, UserSession userSession)
        {
            ProfileRepository = profileRepository;
            UserRepository = userRepository;
            UserSession = userSession;
        }

        [LoggedIn]
        [HttpGet]
        public ActionResult Edit()
        {
            UserProfile? model = this.ProfileRepository.GetByLogin(this.UserSession.LoggedInUser.Login)?.GetData<UserProfile>();

            if (model is null)
            {
                throw new Exception("User profile not found");
            }

            return this.View(model);
        }

        [HttpPost]
        [LoggedIn]
        public ActionResult Edit(UserProfile model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            using (IWriteContext context = ProfileRepository.WriteContext())
            {
                UserProfile existing = this.ProfileRepository.GetByLogin(this.UserSession.LoggedInUser.Login);

                if (!(existing is null))
                {
                    model.User = this.UserSession.LoggedInUser;

                    existing.SetData(model);
                }
                else
                {
                    existing = new UserProfile();

                    model.User = this.UserSession.LoggedInUser;

                    existing.User = this.UserRepository.Find(this.UserSession.LoggedInUser._Id);

                    existing.SetData(model);
                }

                this.ProfileRepository.AddOrUpdate(existing);
            }

            return this.RedirectToAction(nameof(V), new { area = "" });
        }

        public ActionResult V(string Username)
        {
            UserProfile? profile = null;

            if (string.IsNullOrWhiteSpace(Username))
            {
                if (this.UserSession.IsLoggedIn)
                {
                    profile = this.ProfileRepository.GetByLogin(this.UserSession.LoggedInUser?.Login)?.GetData<UserProfile>();

                    if (!(profile is null))
                    {
                        profile.User = this.UserSession.LoggedInUser;
                    }
                }
            }
            else
            {
                profile = this.ProfileRepository.GetByLogin(Username)?.GetData<UserProfile>();
            }

            if (profile is null)
            {
                profile = new UserProfile
                {
                    User = this.UserRepository.GetByLogin(Username)
                };
            }

            return this.View(profile);
        }
    }
}