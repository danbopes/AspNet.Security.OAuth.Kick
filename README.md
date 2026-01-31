# AspNet.Security.OAuth.Kick

ASP.NET Core OAuth 2.0 authentication provider for [Kick](https://kick.com).

[![NuGet](https://img.shields.io/nuget/v/Danbopes.AspNet.Security.OAuth.Kick.svg)](https://www.nuget.org/packages/Danbopes.AspNet.Security.OAuth.Kick/)
[![Build](https://github.com/danbopes/AspNet.Security.OAuth.Kick/actions/workflows/ci.yml/badge.svg)](https://github.com/danbopes/AspNet.Security.OAuth.Kick/actions/workflows/ci.yml)

## Installation

```bash
dotnet add package Danbopes.AspNet.Security.OAuth.Kick
```

## Usage

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = KickAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie()
.AddKick(options =>
{
    options.ClientId = builder.Configuration["Kick:ClientId"]!;
    options.ClientSecret = builder.Configuration["Kick:ClientSecret"]!;
});
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `ClientId` | Your Kick OAuth application client ID | Required |
| `ClientSecret` | Your Kick OAuth application client secret | Required |
| `CallbackPath` | The path where Kick redirects after authentication | `/signin-kick` |
| `Scope` | OAuth scopes to request | `user:read` |
| `SaveTokens` | Whether to store tokens in the authentication properties | `false` |

## Claims

The following claims are mapped from the Kick user profile:

| Claim Type | Description |
|------------|-------------|
| `ClaimTypes.NameIdentifier` | User ID |
| `ClaimTypes.Name` | Display name |
| `ClaimTypes.Email` | Email address |
| `urn:kick:profilepicture` | Profile picture URL |

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
