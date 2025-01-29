// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Pipeline;

namespace Azure.Identity
{
    /// <summary>
    /// Provides a <see cref="TokenCredential"/> implementation which chains the <see cref="EnvironmentCredential"/> and <see cref="ManagedIdentityCredential"/> implementations to be tried in order
    /// until one of the getToken methods returns a non-default <see cref="AccessToken"/>.
    /// </summary>
    /// <remarks>
    /// This credential is designed for applications deployed to Azure <see cref="DefaultAzureCredential"/> is
    /// better suited to local development). It authenticates service principals and managed identities..
    /// </remarks>
    internal class AzureFederatedIdentityCredential : TokenCredential
    {
        private static string s_oidcAudience = "api://AzureADTokenExchange/.default";
        private static TokenRequestContext s_msiFederatedTokenRequestContext = new TokenRequestContext(new[] { s_oidcAudience });

        private readonly ManagedIdentityCredential _managedIdentityCredential;
        private readonly ClientAssertionCredential _clientAssertionCredential;

        /// <summary>
        /// Initializes an instance of the <see cref="AzureApplicationCredential"/>.
        /// </summary>
        public AzureFederatedIdentityCredential() : this(new AzureFederatedIdentityCredentialOptions(), null, null)
        { }

        /// <summary>
        /// Initializes an instance of the <see cref="AzureApplicationCredential"/>.
        /// </summary>
        /// <param name="options">The <see cref="TokenCredentialOptions"/> to configure this credential.</param>
        public AzureFederatedIdentityCredential(AzureFederatedIdentityCredentialOptions options) : this(options ?? new AzureFederatedIdentityCredentialOptions(), null, null)
        { }

        internal AzureFederatedIdentityCredential(AzureFederatedIdentityCredentialOptions options, EnvironmentCredential environmentCredential = null, ManagedIdentityCredential managedIdentityCredential = null)
        {
            // first acquire the managed identity credential.
            _managedIdentityCredential = new ManagedIdentityCredential(options.ManagedIdentityId._userAssignedId);
            // second new up the ClientAssertionCredential which can be used to get the token from the managed identity.
            _clientAssertionCredential = new ClientAssertionCredential(
                options.FederatedApplicationTenantId,
                options.FederatedApplicationId.ToString(),
                async ct => (await _managedIdentityCredential.GetTokenAsync(s_msiFederatedTokenRequestContext, ct).ConfigureAwait(false)).Token,
                new ClientAssertionCredentialOptions()
                );
            );
        }

        /// <summary>
        /// Calls <see cref="TokenCredential.GetToken"/> on the <see cref="ClientAssertionCredential"/> with appropriate parameters to impersonate the federated application using the
        /// specified managed identity. Where possible, <see href="https://aka.ms/azsdk/net/identity/credential-reuse">reuse credential instances</see>
        /// to optimize cache effectiveness.
        /// </summary>
        /// <param name="requestContext">The details of the authentication request.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> controlling the request lifetime.</param>
        /// <returns>The <see cref="AccessToken"/> return by the <see cref="ClientAssertionCredential"/>.</returns>
        /// <exception cref="AuthenticationFailedException">Thrown when the authentication failed.</exception>
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken = default)
            => GetTokenImplAsync(false, requestContext, cancellationToken).EnsureCompleted();

        /// <summary>
        /// Calls <see cref="TokenCredential.GetToken"/> on the <see cref="ClientAssertionCredential"/> with appropriate parameters to impersonate the federated application using the
        /// specified managed identity. Where possible, <see href="https://aka.ms/azsdk/net/identity/credential-reuse">reuse credential instances</see>
        /// to optimize cache effectiveness.
        /// </summary>
        /// <param name="requestContext">The details of the authentication request.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> controlling the request lifetime.</param>
        /// <returns>The <see cref="AccessToken"/> return by the <see cref="ClientAssertionCredential"/>.</returns>
        /// <exception cref="AuthenticationFailedException">Thrown when the authentication failed.</exception>
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken = default)
            => await GetTokenImplAsync(true, requestContext, cancellationToken).ConfigureAwait(false);

        private async ValueTask<AccessToken> GetTokenImplAsync(bool async, TokenRequestContext requestContext, CancellationToken cancellationToken)
        => async ?
            await _clientAssertionCredential.GetTokenAsync(requestContext, cancellationToken).ConfigureAwait(false)
            : _clientAssertionCredential.GetToken(requestContext, cancellationToken);
    }
}
