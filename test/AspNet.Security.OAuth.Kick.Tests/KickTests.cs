/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/danbopes/AspNet.Security.OAuth.Kick for more information.
 */

using System.Net;
using System.Security.Claims;
using System.Text.Json;
using AspNet.Security.OAuth.Kick;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AspNet.Security.OAuth.Kick.Tests;

public class KickClaimMappingTests
{
    private const string UserInfoJson = """
        {
            "data": [{
                "user_id": "12345",
                "name": "dallas",
                "email": "dallas@kick.com",
                "profile_picture": "https://files.kick.com/images/user/12345/profile.webp"
            }]
        }
        """;

    [Theory]
    [InlineData(ClaimTypes.NameIdentifier, "12345")]
    [InlineData(ClaimTypes.Name, "dallas")]
    [InlineData(ClaimTypes.Email, "dallas@kick.com")]
    [InlineData(KickAuthenticationConstants.Claims.ProfilePicture, "https://files.kick.com/images/user/12345/profile.webp")]
    public void ClaimActions_ExtractsExpectedValue(string claimType, string expectedValue)
    {
        // Arrange
        var options = new KickAuthenticationOptions();
        using var document = JsonDocument.Parse(UserInfoJson);
        var identity = new ClaimsIdentity();

        // Act
        foreach (var action in options.ClaimActions)
        {
            action.Run(document.RootElement, identity, "Kick");
        }

        // Assert
        var claim = identity.FindFirst(claimType);
        Assert.NotNull(claim);
        Assert.Equal(expectedValue, claim.Value);
    }

    [Fact]
    public void ClaimActions_HandlesNumericUserId()
    {
        var json = """
            {
                "data": [{
                    "user_id": 98765,
                    "name": "numeric_user"
                }]
            }
            """;

        var options = new KickAuthenticationOptions();
        using var document = JsonDocument.Parse(json);
        var identity = new ClaimsIdentity();

        foreach (var action in options.ClaimActions)
        {
            action.Run(document.RootElement, identity, "Kick");
        }

        var claim = identity.FindFirst(ClaimTypes.NameIdentifier);
        Assert.NotNull(claim);
        Assert.Equal("98765", claim.Value);
    }

    [Fact]
    public void ClaimActions_HandlesEmptyDataArray()
    {
        var json = """{ "data": [] }""";

        var options = new KickAuthenticationOptions();
        using var document = JsonDocument.Parse(json);
        var identity = new ClaimsIdentity();

        foreach (var action in options.ClaimActions)
        {
            action.Run(document.RootElement, identity, "Kick");
        }

        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimActions_HandlesMissingDataProperty()
    {
        var json = """{ "user_id": "123", "name": "test" }""";

        var options = new KickAuthenticationOptions();
        using var document = JsonDocument.Parse(json);
        var identity = new ClaimsIdentity();

        foreach (var action in options.ClaimActions)
        {
            action.Run(document.RootElement, identity, "Kick");
        }

        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimActions_HandlesMissingOptionalFields()
    {
        var json = """
            {
                "data": [{
                    "user_id": "123",
                    "name": "minimal_user"
                }]
            }
            """;

        var options = new KickAuthenticationOptions();
        using var document = JsonDocument.Parse(json);
        var identity = new ClaimsIdentity();

        foreach (var action in options.ClaimActions)
        {
            action.Run(document.RootElement, identity, "Kick");
        }

        Assert.NotNull(identity.FindFirst(ClaimTypes.NameIdentifier));
        Assert.NotNull(identity.FindFirst(ClaimTypes.Name));
        Assert.Null(identity.FindFirst(ClaimTypes.Email));
        Assert.Null(identity.FindFirst(KickAuthenticationConstants.Claims.ProfilePicture));
    }
}

public class KickOptionsTests
{
    [Fact]
    public void DefaultOptions_HasCorrectAuthorizationEndpoint()
    {
        var options = new KickAuthenticationOptions();
        Assert.Equal("https://id.kick.com/oauth/authorize", options.AuthorizationEndpoint);
    }

    [Fact]
    public void DefaultOptions_HasCorrectTokenEndpoint()
    {
        var options = new KickAuthenticationOptions();
        Assert.Equal("https://id.kick.com/oauth/token", options.TokenEndpoint);
    }

    [Fact]
    public void DefaultOptions_HasCorrectUserInformationEndpoint()
    {
        var options = new KickAuthenticationOptions();
        Assert.Equal("https://api.kick.com/public/v1/users", options.UserInformationEndpoint);
    }

    [Fact]
    public void DefaultOptions_HasCorrectCallbackPath()
    {
        var options = new KickAuthenticationOptions();
        Assert.Equal("/signin-kick", options.CallbackPath);
    }

    [Fact]
    public void DefaultOptions_HasPkceEnabled()
    {
        var options = new KickAuthenticationOptions();
        Assert.True(options.UsePkce);
    }

    [Fact]
    public void DefaultOptions_HasUserReadScope()
    {
        var options = new KickAuthenticationOptions();
        Assert.Contains("user:read", options.Scope);
    }

    [Fact]
    public void DefaultOptions_HasCorrectClaimsIssuer()
    {
        var options = new KickAuthenticationOptions();
        Assert.Equal("Kick", options.ClaimsIssuer);
    }
}

public class KickChallengeTests : IAsyncLifetime
{
    private IHost? _host;
    private HttpClient? _client;

    public async Task InitializeAsync()
    {
        _host = await CreateHostAsync();
        _client = _host.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client?.Dispose();
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    [Fact]
    public async Task Challenge_RedirectsToKickAuthorization()
    {
        var response = await _client!.GetAsync("/challenge");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("id.kick.com/oauth/authorize", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Challenge_IncludesResponseTypeCode()
    {
        var response = await _client!.GetAsync("/challenge");

        Assert.Contains("response_type=code", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Challenge_IncludesUserReadScope()
    {
        var response = await _client!.GetAsync("/challenge");

        Assert.Contains("scope=user%3Aread", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Challenge_IncludesPkceCodeChallenge()
    {
        var response = await _client!.GetAsync("/challenge");

        var location = response.Headers.Location!.ToString();
        Assert.Contains("code_challenge=", location);
        Assert.Contains("code_challenge_method=S256", location);
    }

    [Fact]
    public async Task Challenge_IncludesClientId()
    {
        var response = await _client!.GetAsync("/challenge");

        Assert.Contains("client_id=test_client_id", response.Headers.Location!.ToString());
    }

    private static async Task<IHost> CreateHostAsync()
    {
        var builder = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthentication(options =>
                    {
                        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme = KickAuthenticationDefaults.AuthenticationScheme;
                    })
                    .AddCookie()
                    .AddKick(options =>
                    {
                        options.ClientId = "test_client_id";
                        options.ClientSecret = "test_client_secret";
                    });
                });
                webBuilder.Configure(app =>
                {
                    app.UseAuthentication();
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/challenge", async context =>
                        {
                            await context.ChallengeAsync(KickAuthenticationDefaults.AuthenticationScheme);
                        });
                    });
                });
            });

        return await builder.StartAsync();
    }
}

public class KickDefaultsTests
{
    [Fact]
    public void AuthenticationScheme_IsKick()
    {
        Assert.Equal("Kick", KickAuthenticationDefaults.AuthenticationScheme);
    }

    [Fact]
    public void DisplayName_IsKick()
    {
        Assert.Equal("Kick", KickAuthenticationDefaults.DisplayName);
    }

    [Fact]
    public void Issuer_IsKick()
    {
        Assert.Equal("Kick", KickAuthenticationDefaults.Issuer);
    }

    [Fact]
    public void CallbackPath_IsSignInKick()
    {
        Assert.Equal("/signin-kick", KickAuthenticationDefaults.CallbackPath);
    }
}

public class KickConstantsTests
{
    [Fact]
    public void ProfilePictureClaim_HasCorrectUrn()
    {
        Assert.Equal("urn:kick:profilepicture", KickAuthenticationConstants.Claims.ProfilePicture);
    }
}
