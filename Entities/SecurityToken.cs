using Newtonsoft.Json;
using Penguin.Shared.Objects;
using System;
using System.Collections.Generic;

namespace Penguin.Cms.Modules.Security.Entities
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

    public partial class Connection
    {
        [JsonProperty("rtt")]
        public long Rtt { get; set; }

        [JsonProperty("saveData")]
        public bool? SaveData { get; set; }
    }

    public partial class Date
    {
        [JsonProperty("current")]
        public DateTimeOffset Current { get; set; }

        [JsonProperty("local")]
        public string? Local { get; set; }

        [JsonProperty("offset")]
        public long Offset { get; set; }
    }

    public partial class History
    {
        [JsonProperty("length")]
        public long Length { get; set; }
    }

    public partial class MimeType
    {
        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string? Description { get; set; }

        [JsonProperty("suffixes", NullValueHandling = NullValueHandling.Ignore)]
        public string? Suffixes { get; set; }

        [JsonProperty("type", NullValueHandling = NullValueHandling.Ignore)]
        public string? Type { get; set; }
    }

    public partial class Navigator
    {
        [JsonProperty("appCodeName")]
        public string? AppCodeName { get; set; }

        [JsonProperty("appName")]
        public string? AppName { get; set; }

        [JsonProperty("appVersion")]
        public string? AppVersion { get; set; }

        [JsonProperty("connection")]
        public Connection? Connection { get; set; }

        [JsonProperty("cookieEnabled")]
        public bool? CookieEnabled { get; set; }

        [JsonProperty("deviceMemory")]
        public long DeviceMemory { get; set; }

        [JsonProperty("doNotTrack")]
        public string? DoNotTrack { get; set; }

        [JsonProperty("hardwareConcurrency")]
        public long HardwareConcurrency { get; set; }

        [JsonProperty("language")]
        public string? Language { get; set; }

        [JsonProperty("languages")]
        public List<string>? Languages { get; set; }

        [JsonProperty("maxTouchPoints")]
        public long MaxTouchPoints { get; set; }

        [JsonProperty("mimeTypes")]
        public List<MimeType>? MimeTypes { get; set; }

        [JsonProperty("oscpu")]
        public string? OSCpu { get; set; }

        [JsonProperty("platform")]
        public string? Platform { get; set; }

        [JsonProperty("plugins")]
        public List<Plugin>? Plugins { get; set; }

        [JsonProperty("product")]
        public string? Product { get; set; }

        [JsonProperty("productSub")]
        public string? ProductSub { get; set; }

        [JsonProperty("userAgent")]
        public string? UserAgent { get; set; }

        [JsonProperty("vendor")]
        public string? Vendor { get; set; }

        [JsonProperty("vendorSub")]
        public string? VendorSub { get; set; }
    }

    public partial class Orientation
    {
        [JsonProperty("angle")]
        public long Angle { get; set; }

        [JsonProperty("type")]
        public string? Type { get; set; }
    }

    public partial class Plugin
    {
        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string? Description { get; set; }

        [JsonProperty("filename", NullValueHandling = NullValueHandling.Ignore)]
        public string? Filename { get; set; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string? Name { get; set; }
    }

    public partial class Screen
    {
        [JsonProperty("availHeight")]
        public long AvailHeight { get; set; }

        [JsonProperty("availLeft")]
        public long AvailLeft { get; set; }

        [JsonProperty("availTop")]
        public long AvailTop { get; set; }

        [JsonProperty("availWidth")]
        public long AvailWidth { get; set; }

        [JsonProperty("colorDepth")]
        public long ColorDepth { get; set; }

        [JsonProperty("height")]
        public long Height { get; set; }

        [JsonProperty("orientation")]
        public Orientation? Orientation { get; set; }

        [JsonProperty("pixelDepth")]
        public long PixelDepth { get; set; }

        [JsonProperty("width")]
        public long Width { get; set; }
    }

    public partial class SecurityToken
    {
        [JsonProperty("canvas")]
        public long Canvas { get; set; }

        [JsonProperty("date")]
        public Date? Date { get; set; }

        [JsonProperty("devicePixelRatio")]
        public double DevicePixelRatio { get; set; }

        [JsonProperty("history")]
        public History? History { get; set; }

        [JsonProperty("innerHeight")]
        public long InnerHeight { get; set; }

        [JsonProperty("innerWidth")]
        public long InnerWidth { get; set; }

        public TFE IsBlocked { get; set; }
        public TFE IsTor { get; set; }

        [JsonProperty("navigator")]
        public Navigator? Navigator { get; set; }

        [JsonProperty("outerHeight")]
        public long OuterHeight { get; set; }

        [JsonProperty("outerWidth")]
        public long OuterWidth { get; set; }

        [JsonProperty("screen")]
        public Screen? Screen { get; set; }

        [JsonProperty("styleMedia")]
        public StyleMedia? StyleMedia { get; set; }
    }

    public partial class StyleMedia
    {
    }

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}