using Penguin.Cms.Security;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Penguin.Cms.Modules.Security.Services
{
    public partial class UserService
    {
        private class LoginModel
        {
            public string AuthenticationEmail
            {
                get
                {
                    if (string.IsNullOrWhiteSpace(Domain) && !Login.Contains('@', StringComparison.OrdinalIgnoreCase))
                    {
                        return string.Empty;
                    }
                    else if (!Login.Contains('@', StringComparison.OrdinalIgnoreCase))
                    {
                        //TODO: Make this better;
                        return $"{Login}@{Domain}.com";
                    }
                    else
                    {
                        return Login;
                    }
                }
            }

            public string Domain { get; set; }

            public List<Validation> Validations { get; } = new List<Validation>();

            public bool InDatabase { get; set; }

            public bool IsValidated => Validations.Any(v => v.Succeeded);

            public string Login { get; set; }

            public string Password { get; set; }

            public bool RequiresSave { get; set; }

            public User? ThisUser { get; set; }
			public bool IsExternal { get; internal set; }

			public LoginModel(string login, string password, string domain = "")
            {
                Login = login;
                Password = password;
                Domain = domain;
            }
        }
    }
}