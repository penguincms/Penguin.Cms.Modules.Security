using Penguin.Persistence.Abstractions;
using Penguin.Persistence.Abstractions.Attributes.Relations;
using Penguin.Persistence.Abstractions.Models.Complex;

namespace Penguin.Cms.Modules.Security.Models
{
    [ComplexType]
    public class BrowserFingerprint
    {
    }

    public class ClientFingerprint : KeyedObject
    {
        public string AppName { get; set; } = string.Empty;
        public string AppVersion { get; set; } = string.Empty;
        public string CodeName { get; set; } = string.Empty;
        public bool cookieEnabled { get; set; }
        public string Language { get; set; } = string.Empty;
        public bool OnLine { get; set; }
        public float PixelRatio { get; set; }
        public Size? Screen { get; set; }
        public Size? ViewPort { get; set; }
    }

    [ComplexType]
    public class ServerFingerprint
    {
    }
}