using Penguin.Cms.Security;
using System;

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

            public Validation DomainValidation { get; set; }

            public Validation ExchangeValidation { get; set; }

            public bool InDatabase { get; set; }

            public bool IsValidated => OwaValidation.Succeeded || DomainValidation.Succeeded || LocalValidation.Succeeded || ExchangeValidation.Succeeded;

            public Validation LocalValidation { get; set; }

            public string Login { get; set; }

            public Validation OwaValidation { get; set; }

            public string Password { get; set; }

            public bool RequiresSave { get; set; }

            public User? ThisUser { get; set; }

            public LoginModel(string login, string password, string domain = "")
            {
                Login = login;
                Password = password;
                Domain = domain;

                OwaValidation = new Validation();
                DomainValidation = new Validation();
                LocalValidation = new Validation();
                ExchangeValidation = new Validation();
            }
        }
    }
}