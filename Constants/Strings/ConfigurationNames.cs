﻿using System.Diagnostics.CodeAnalysis;

namespace Penguin.Cms.Modules.Security.Constants.Strings
{
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores")]
    public static partial class ConfigurationNames
    {
        public const string ALLOW_DUPLICATE_EMAIL = "AllowDuplicateEmail";
        public const string AUTOMATIC_USER_REGISTRATION = "AutomaticUserRegistration";
        public const string CONNECTION_STRINGS_REPORTING = "ConnectionStrings.Reporting";
        public const string DOMAIN_LOGIN = "DomainLogin";
        public const string DOMAIN_NAME = "DomainName";
        public const string DISABLE_LOCAL_LOGIN = "DisableLocalLogin";
        public const string MANUAL_USER_REGISTRATION = "ManualUserRegistration";
        public const string OWA_LOGIN = "OWALogin";
        public const string REQUIRE_EMAIL_VALIDATION = "RequireEmailValidation";
    }
}