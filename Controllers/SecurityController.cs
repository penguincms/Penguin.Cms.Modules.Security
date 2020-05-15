using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Penguin.Cms.Modules.Security.Entities;
using Penguin.Cms.Modules.Security.Services;
using Penguin.Cms.Security;
using Penguin.Cms.Security.Constants;
using Penguin.Cms.Security.Repositories;
using Penguin.Persistence.Abstractions.Interfaces;
using Penguin.Security.Abstractions.Interfaces;
using Penguin.Security.Encryption;
using Penguin.Web.Extensions;
using System;
using System.Linq;

namespace Penguin.Cms.Modules.Security.Controllers
{
    public class SecurityController : Controller
    {
        protected IRepository<Group> GroupRepository { get; set; }
        protected IHostingEnvironment HostingEnvironment { get; set; }
        protected IRepository<Role> RoleRepository { get; set; }
        protected ISession Session { get; set; }
        protected UserRepository UserRepository { get; set; }
        protected IUserSession UserSession { get; set; }

        public SecurityController(ISession session, IRepository<Group> groupRepository, IRepository<Role> roleRepository, IHostingEnvironment hostingEnvironment, UserRepository userRepository, IUserSession userSession)
        {
            this.Session = session;
            this.UserSession = userSession;
            this.UserRepository = userRepository;
            this.GroupRepository = groupRepository;
            this.RoleRepository = roleRepository;
            this.HostingEnvironment = hostingEnvironment;
        }

        public ActionResult Fingerprint([FromBody] string content)
        {
            TeaEncryptor tea = new TeaEncryptor(this.Session.Get(SecurityService.SECURITY_TOKEN_PASSWORD_NAME));

            string json = tea.Decrypt(content);

            SecurityToken token = JsonConvert.DeserializeObject<SecurityToken>(json);

            this.Session.Set(SecurityService.SECURITY_TOKEN_NAME, token);

            return this.Content("");
        }

        public FileContentResult Image()
        {
            string FilePath = this.HostingEnvironment.ContentRootPath + SecurityService.IMAGE_ROOT + "Security.png";
            byte[] toReturn;
            byte[] password = new byte[SecurityService.PASSWORD_LENGTH];
            Random r = new Random();

            r.NextBytes(password);

            if (System.IO.File.Exists(FilePath))
            {
                toReturn = System.IO.File.ReadAllBytes(FilePath).ToList().Concat(password).ToArray();
            }
            else
            {
                toReturn = new byte[SecurityService.DUMMY_FILE_LENGTH + SecurityService.PASSWORD_LENGTH];

                r.NextBytes(toReturn);

                for (int i = 0; i < SecurityService.PASSWORD_LENGTH; i++)
                {
                    toReturn[SecurityService.DUMMY_FILE_LENGTH + i] = password[i];
                }
            }

            this.Session.Set(SecurityService.SECURITY_TOKEN_PASSWORD_NAME, password);

            return this.File(toReturn, "image/png", System.IO.Path.GetFileName(SecurityService.SecurityImage));
        }

        public ActionResult UserRecord(Guid Model)
        {
            User toView = this.UserRepository.Find(Model) ?? Users.Guest;

            return this.View("UserRecord", toView);
        }
    }
}