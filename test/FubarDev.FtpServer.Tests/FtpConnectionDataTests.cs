// <copyright file="FtpConnectionDataTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Text;

using FubarDev.FtpServer.Features;
using FubarDev.FtpServer.Localization;

using Microsoft.AspNetCore.Http.Features;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    // REIN resets the session layer by calling this same initializer again; this is the mechanism that guarantees it.
    public class FtpConnectionDataTests
    {
        [Fact]
        public void InitializeSessionFeatures_AlwaysCreatesFreshInstances()
        {
            var features = new FeatureCollection();
            var catalogLoader = new DefaultFtpCatalogLoader();

            FtpConnectionData.InitializeSessionFeatures(features, Encoding.ASCII, catalogLoader);

            var authorizationFeature = features.Get<IAuthorizationInformationFeature>()!;
            authorizationFeature.FtpUser = new System.Security.Claims.ClaimsPrincipal();
            var fileSystemFeature = features.Get<IFileSystemFeature>()!;
            var encodingFeature = features.Get<IEncodingFeature>()!;
            var localizationFeature = features.Get<ILocalizationFeature>()!;
            var transferConfigurationFeature = features.Get<ITransferConfigurationFeature>()!;
            localizationFeature.Language = new System.Globalization.CultureInfo("da");

            FtpConnectionData.InitializeSessionFeatures(features, Encoding.ASCII, catalogLoader);

            Assert.NotSame(authorizationFeature, features.Get<IAuthorizationInformationFeature>());
            Assert.Null(features.Get<IAuthorizationInformationFeature>()!.FtpUser);
            Assert.NotSame(fileSystemFeature, features.Get<IFileSystemFeature>());
            Assert.NotSame(encodingFeature, features.Get<IEncodingFeature>());
            Assert.NotSame(localizationFeature, features.Get<ILocalizationFeature>());
            Assert.Equal("en", features.Get<ILocalizationFeature>()!.Language.TwoLetterISOLanguageName);
            Assert.NotSame(transferConfigurationFeature, features.Get<ITransferConfigurationFeature>());
        }
    }
}
