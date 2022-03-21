using Microsoft.AspNetCore.Mvc;
using Penguin.Cms.Security.Constants;
using Penguin.Cms.Security.Repositories;
using System;

namespace Penguin.Cms.Modules.Security.ViewComponents
{
    public class UserRecord : ViewComponent
    {
        protected UserRepository UserRepository { get; set; }

        public UserRecord(UserRepository userRepository)
        {
            this.UserRepository = userRepository;
        }

        public IViewComponentResult Invoke(Guid Model) => this.View("~/Views/Security/UserRecord.cshtml", this.UserRepository.Find(Model) ?? Users.Guest);
    }
}