/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/danbopes/AspNet.Security.OAuth.Kick for more information.
 */

using AspNet.Security.OAuth.Kick;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods to add Kick authentication to <see cref="AuthenticationBuilder"/>.
/// </summary>
public static class KickAuthenticationExtensions
{
    /// <summary>
    /// Adds Kick authentication to the <see cref="AuthenticationBuilder"/> using the default scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthenticationBuilder AddKick(this AuthenticationBuilder builder)
    {
        return builder.AddKick(KickAuthenticationDefaults.AuthenticationScheme, _ => { });
    }

    /// <summary>
    /// Adds Kick authentication to the <see cref="AuthenticationBuilder"/> using the default scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configuration">The delegate used to configure the Kick options.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthenticationBuilder AddKick(
        this AuthenticationBuilder builder,
        Action<KickAuthenticationOptions> configuration)
    {
        return builder.AddKick(KickAuthenticationDefaults.AuthenticationScheme, configuration);
    }

    /// <summary>
    /// Adds Kick authentication to the <see cref="AuthenticationBuilder"/> using the specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="configuration">The delegate used to configure the Kick options.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthenticationBuilder AddKick(
        this AuthenticationBuilder builder,
        string scheme,
        Action<KickAuthenticationOptions> configuration)
    {
        return builder.AddKick(scheme, KickAuthenticationDefaults.DisplayName, configuration);
    }

    /// <summary>
    /// Adds Kick authentication to the <see cref="AuthenticationBuilder"/> using the specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="caption">A display name for the authentication handler.</param>
    /// <param name="configuration">The delegate used to configure the Kick options.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthenticationBuilder AddKick(
        this AuthenticationBuilder builder,
        string scheme,
        string caption,
        Action<KickAuthenticationOptions> configuration)
    {
        return builder.AddOAuth<KickAuthenticationOptions, KickAuthenticationHandler>(scheme, caption, configuration);
    }
}
