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

            public string Domain { get; set; }

            public Validation DomainValidation { get; set; }
            public Validation ExchangeValidation { get; set; }

            public bool InDatabase { get; set; }

            public bool IsValidated => this.OwaValidation.Succeeded || this.DomainValidation.Succeeded || this.LocalValidation.Succeeded || this.ExchangeValidation.Succeeded;

            public Validation LocalValidation { get; set; }

            public string Login { get; set; }
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
                this.ExchangeValidation = new Validation();
            }
        }
    }
}