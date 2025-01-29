// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Pipeline;

namespace Azure.Identity
{
    /// <summary>
    /// Provides an easy wrapper around <see cref="ClientAssertionCredential"/> for use with Azure Federated Identity when trying to acquire a <see cref="TokenCredential"/>.
    /// </summary>
    /// <remarks>
    /// This credential is designed for applications deployed to Azure. <see cref="DefaultAzureCredential"/> which need or desire to authenticate across tenants using
    /// a federated application.
    /// </remarks>
    internal class AzureFederatedIdentityCredential : TokenCredential
    {
        private static string s_oidcAudience = "api://AzureADTokenExchange/.default";
        private static TokenRequestContext s_msiFederatedTokenRequestContext = new TokenRequestContext(new[] { s_oidcAudience });

        private readonly AzureFederatedIdentityCredentialOptions _options;
        private readonly ManagedIdentityCredential _managedIdentityCredential;
        private readonly ConcurrentDictionary<string, Lazy<ClientAssertionCredential>> _clientAssertionCredentials = new();

        /// <summary>
        /// Initializes an instance of the <see cref="AzureFederatedIdentityCredential"/>.
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
            _managedIdentityCredential = new ManagedIdentityCredential(options.ManagedIdentityId._userAssignedId);
            _options = options;
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
        {
            // Get or create a client assertion credential for the federated application in the given tenant
            ClientAssertionCredential
                _clientAssertionCredential =
                    _clientAssertionCredentials.AddOrUpdate(
                        requestContext.TenantId,
                        // use lazy to avoid the expensive cost if of ClientAssertionCredential creation if thread contention is high
                        new Lazy<ClientAssertionCredential>(
                            () => new ClientAssertionCredential(
                                    requestContext.TenantId,
                                    _options.FederatedApplicationId.ToString(),
                                    async ct => (await _managedIdentityCredential.GetTokenAsync(s_msiFederatedTokenRequestContext, ct).ConfigureAwait(false)).Token)
                        ),
                        (_, existing) => existing
                    ).Value;

            return async?
                await _clientAssertionCredential.GetTokenAsync(requestContext, cancellationToken).ConfigureAwait(false)
                : _clientAssertionCredential.GetToken(requestContext, cancellationToken);
        }
    }
}
