using Microsoft.AspNetCore.Mvc;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Extensions;
using Penguin.Cms.Security.Repositories;
using Penguin.Cms.Web.Security;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Web.Security.Attributes;
using System;

namespace Penguin.Cms.Modules.Security.Controllers
{
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
            UserProfile? model = ProfileRepository.GetByLogin(UserSession.LoggedInUser.Login)?.GetData<UserProfile>();

            return model is null ? throw new Exception("User profile not found") : View(model);
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
                UserProfile existing = ProfileRepository.GetByLogin(UserSession.LoggedInUser.Login);

                if (existing is not null)
                {
                    model.User = UserSession.LoggedInUser;

                    existing.SetData(model);
                }
                else
                {
                    existing = new UserProfile();

                    model.User = UserSession.LoggedInUser;

                    existing.User = UserRepository.Find(UserSession.LoggedInUser._Id);

                    existing.SetData(model);
                }

                ProfileRepository.AddOrUpdate(existing);
            }

            return RedirectToAction(nameof(V), new { area = "" });
        }

        public ActionResult V(string Username)
        {
            UserProfile? profile = null;

            if (string.IsNullOrWhiteSpace(Username))
            {
                if (UserSession.IsLoggedIn)
                {
                    profile = ProfileRepository.GetByLogin(UserSession.LoggedInUser?.Login)?.GetData<UserProfile>();

                    if (profile is not null)
                    {
                        profile.User = UserSession.LoggedInUser;
                    }
                }
            }
            else
            {
                profile = ProfileRepository.GetByLogin(Username)?.GetData<UserProfile>();
            }

            profile ??= new UserProfile
            {
                User = UserRepository.GetByLogin(Username)
            };

            return View(profile);
        }
    }
}