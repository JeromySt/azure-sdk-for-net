// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using NUnit.Framework;

namespace Azure.ResourceManager.Storage.Samples
{
    public partial class Sample_EncryptionScopeCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_StorageAccountPutEncryptionScope()
        {
            // Generated from example definition: specification/storage/resource-manager/Microsoft.Storage/stable/2024-01-01/examples/StorageAccountPutEncryptionScope.json
            // this example is just showing the usage of "EncryptionScopes_Put" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this StorageAccountResource created on azure
            // for more information of creating StorageAccountResource, please refer to the document of StorageAccountResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "resource-group-name";
            string accountName = "accountname";
            ResourceIdentifier storageAccountResourceId = StorageAccountResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, accountName);
            StorageAccountResource storageAccount = client.GetStorageAccountResource(storageAccountResourceId);

            // get the collection of this EncryptionScopeResource
            EncryptionScopeCollection collection = storageAccount.GetEncryptionScopes();

            // invoke the operation
            string encryptionScopeName = "{encryption-scope-name}";
            EncryptionScopeData data = new EncryptionScopeData();
            ArmOperation<EncryptionScopeResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, encryptionScopeName, data);
            EncryptionScopeResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            EncryptionScopeData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_StorageAccountPutEncryptionScopeWithInfrastructureEncryption()
        {
            // Generated from example definition: specification/storage/resource-manager/Microsoft.Storage/stable/2024-01-01/examples/StorageAccountPutEncryptionScopeWithInfrastructureEncryption.json
            // this example is just showing the usage of "EncryptionScopes_Put" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this StorageAccountResource created on azure
            // for more information of creating StorageAccountResource, please refer to the document of StorageAccountResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "resource-group-name";
            string accountName = "accountname";
            ResourceIdentifier storageAccountResourceId = StorageAccountResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, accountName);
            StorageAccountResource storageAccount = client.GetStorageAccountResource(storageAccountResourceId);

            // get the collection of this EncryptionScopeResource
            EncryptionScopeCollection collection = storageAccount.GetEncryptionScopes();

            // invoke the operation
            string encryptionScopeName = "{encryption-scope-name}";
            EncryptionScopeData data = new EncryptionScopeData
            {
                RequireInfrastructureEncryption = true,
            };
            ArmOperation<EncryptionScopeResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, encryptionScopeName, data);
            EncryptionScopeResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            EncryptionScopeData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_StorageAccountGetEncryptionScope()
        {
            // Generated from example definition: specification/storage/resource-manager/Microsoft.Storage/stable/2024-01-01/examples/StorageAccountGetEncryptionScope.json
            // this example is just showing the usage of "EncryptionScopes_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this StorageAccountResource created on azure
            // for more information of creating StorageAccountResource, please refer to the document of StorageAccountResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "resource-group-name";
            string accountName = "accountname";
            ResourceIdentifier storageAccountResourceId = StorageAccountResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, accountName);
            StorageAccountResource storageAccount = client.GetStorageAccountResource(storageAccountResourceId);

            // get the collection of this EncryptionScopeResource
            EncryptionScopeCollection collection = storageAccount.GetEncryptionScopes();

            // invoke the operation
            string encryptionScopeName = "{encryption-scope-name}";
            EncryptionScopeResource result = await collection.GetAsync(encryptionScopeName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            EncryptionScopeData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAll_StorageAccountEncryptionScopeList()
        {
            // Generated from example definition: specification/storage/resource-manager/Microsoft.Storage/stable/2024-01-01/examples/StorageAccountEncryptionScopeList.json
            // this example is just showing the usage of "EncryptionScopes_List" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this StorageAccountResource created on azure
            // for more information of creating StorageAccountResource, please refer to the document of StorageAccountResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "resource-group-name";
            string accountName = "accountname";
            ResourceIdentifier storageAccountResourceId = StorageAccountResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, accountName);
            StorageAccountResource storageAccount = client.GetStorageAccountResource(storageAccountResourceId);

            // get the collection of this EncryptionScopeResource
            EncryptionScopeCollection collection = storageAccount.GetEncryptionScopes();

            // invoke the operation and iterate over the result
            await foreach (EncryptionScopeResource item in collection.GetAllAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                EncryptionScopeData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_StorageAccountGetEncryptionScope()
        {
            // Generated from example definition: specification/storage/resource-manager/Microsoft.Storage/stable/2024-01-01/examples/StorageAccountGetEncryptionScope.json
            // this example is just showing the usage of "EncryptionScopes_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this StorageAccountResource created on azure
            // for more information of creating StorageAccountResource, please refer to the document of StorageAccountResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "resource-group-name";
            string accountName = "accountname";
            ResourceIdentifier storageAccountResourceId = StorageAccountResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, accountName);
            StorageAccountResource storageAccount = client.GetStorageAccountResource(storageAccountResourceId);

            // get the collection of this EncryptionScopeResource
            EncryptionScopeCollection collection = storageAccount.GetEncryptionScopes();

            // invoke the operation
            string encryptionScopeName = "{encryption-scope-name}";
            bool result = await collection.ExistsAsync(encryptionScopeName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_StorageAccountGetEncryptionScope()
        {
            // Generated from example definition: specification/storage/resource-manager/Microsoft.Storage/stable/2024-01-01/examples/StorageAccountGetEncryptionScope.json
            // this example is just showing the usage of "EncryptionScopes_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this StorageAccountResource created on azure
            // for more information of creating StorageAccountResource, please refer to the document of StorageAccountResource
            string subscriptionId = "{subscription-id}";
            string resourceGroupName = "resource-group-name";
            string accountName = "accountname";
            ResourceIdentifier storageAccountResourceId = StorageAccountResource.CreateResourceIdentifier(subscriptionId, resourceGroupName, accountName);
            StorageAccountResource storageAccount = client.GetStorageAccountResource(storageAccountResourceId);

            // get the collection of this EncryptionScopeResource
            EncryptionScopeCollection collection = storageAccount.GetEncryptionScopes();

            // invoke the operation
            string encryptionScopeName = "{encryption-scope-name}";
            NullableResponse<EncryptionScopeResource> response = await collection.GetIfExistsAsync(encryptionScopeName);
            EncryptionScopeResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                EncryptionScopeData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}
