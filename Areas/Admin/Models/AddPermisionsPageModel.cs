using Penguin.Cms.Modules.Dynamic.Areas.Admin.Models;
using Penguin.Cms.Security;
using Penguin.Persistence.Abstractions.Attributes.Rendering;
using Penguin.Security.Abstractions;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Penguin.Cms.Modules.Security.Areas.Admin.Models
{
    [SuppressMessage("Usage", "CA2227:Collection properties should be read only")]
    public class AddPermisionsPageModel : UpdateListPageModel
    {
        [Display(Order = -900)]
        public List<SecurityGroup> SecurityGroups { get; set; } = new List<SecurityGroup>();

        [Display(Name = "Permission Name", Order = -800)]
        public PermissionTypes TypeToAdd { get; set; }
    }
}