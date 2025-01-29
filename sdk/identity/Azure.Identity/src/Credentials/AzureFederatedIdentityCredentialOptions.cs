// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Azure.Identity
{
    /// <summary>
    /// Options to configure the <see cref="AzureFederatedIdentityCredential"/> authentication flow and requests made to Azure Identity services.
    /// </summary>
    internal class AzureFederatedIdentityCredentialOptions : TokenCredentialOptions
    {
        /// <summary>
        /// Specifies the client id of the azure ManagedIdentity in the case of user assigned identity.
        /// </summary>
        public ManagedIdentityId ManagedIdentityId { get; set; } = GetManagedIdentityIdFromEnvironment(EnvironmentVariables.ClientId);

        /// <summary>
        /// Specifies the application id of the federated application the managed identity is associated with.
        /// </summary>
        public Guid FederatedApplicationId { get; set; } = GetFederatedApplicationIdFromEnvironment(EnvironmentVariables.FederatedApplicationId);

        private static Guid GetFederatedApplicationIdFromEnvironment(string applicationId)
        {
            return !string.IsNullOrEmpty(applicationId) ? Guid.Parse(applicationId) : Guid.Empty;
        }

        private static ManagedIdentityId GetManagedIdentityIdFromEnvironment(string clientId)
        {
            return !string.IsNullOrEmpty(clientId) ? ManagedIdentityId.FromUserAssignedClientId(clientId) : ManagedIdentityId.SystemAssigned;
        }
    }
}
