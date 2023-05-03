// Copyright (C) Microsoft Corporation. All rights reserved.

using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Management.Batch.Models;
using Microsoft.Azure.Management.DataFactory.Models;
using Microsoft.Azure.Management.ResourceManager;
using Microsoft.DevAI.Core.Configuration;
using Microsoft.DevAI.Logging;
using Microsoft.DevAI.ResourceProvider.API.Auths;
using Microsoft.DevAI.ResourceProvider.API.Exceptions;
using Microsoft.DevAI.ResourceProvider.API.Models;
using Microsoft.DevAI.ResourceProvider.API.Models.Shared;
using Microsoft.DevAI.ResourceProvider.API.Models.Shared.MachinePools;
using Microsoft.DevAI.ResourceProvider.API.Models.Unversioned;
using Microsoft.DevAI.ResourceProvider.API.Models.Unversioned.Instance;
using Microsoft.DevAI.ResourceProvider.API.Models.Unversioned.Sandbox;
using Microsoft.DevAI.ResourceProvider.API.Resources;
using Microsoft.DevAI.ResourceProvider.API.Resources.Aml;
using Microsoft.DevAI.ResourceProvider.API.Resources.DependentResources;
using Microsoft.Extensions.Logging;
using Microsoft.Rest;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using PrivateEndpoint = Microsoft.Azure.Management.Network.Models.PrivateEndpoint;

namespace Microsoft.DevAI.ResourceProvider.API.Helpers
{
    /// <summary>
    /// Common utility functions for the Arm Resource.
    /// </summary>
    public static class ArmResourceHelpers
    {

        private static readonly HttpClient _HttpClient = new HttpClient()
        {
            BaseAddress = new Uri(Common.Configuration.RP.ArmEndpoint)
        };

        /// <summary>
        /// Helper function that creates an ArmResource with relevant context.
        /// </summary>
        /// <typeparam name="TResource">Type of resource wrapper to initialize.</typeparam>
        /// <typeparam name="TResult">Underlying resource type that the wrapper creates.</typeparam>
        /// <typeparam name="TDependents">The related resources associated with the resource wrapper.</typeparam>
        /// <param name="resourceName">Name of the resource to create.</param>
        /// <param name="accessToken">The access token needed to create the resource.</param>
        /// <param name="devAiResource">Context to create a resource in.</param>
        /// <param name="logger">The current <see cref="ILogger"/> instance in context.</param>
        /// <param name="tags">The tags added to the resource.</param>
        /// <param name="relatedResources">Related resources to associate with the resource.</param>
        /// <param name="resourceGroupName">The name of the resource group to create a resource in. If not specified, <paramref name="devAiResource"/> resource group will be used.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The tuple of the resource wrapper that was created and the type produced by resource wrapper.</returns>
        public static async Task<TResource> CreateArmResourceAsync<TResource, TResult, TDependents>(string resourceName, AccessToken accessToken, BaseUnversionedResource devAiResource, ILogger logger, IDictionary<string, string> tags = null, TDependents relatedResources = null, string resourceGroupName = null, CancellationToken cancellationToken = default)
            where TResource : IArmResource<TResult, TDependents>, new()
            where TDependents : class
        {


            var resource = new TResource
            {
                AccessToken = accessToken,
                Logger = logger,
                Name = resourceName,
                RegionName = devAiResource.Location,
                RelatedResources = relatedResources,
                ResourceGroupName = string.IsNullOrWhiteSpace(resourceGroupName) ? devAiResource.ResourceGroupName : resourceGroupName,
                SubscriptionId = devAiResource.SubscriptionId,
                Tags = tags,
                TenantId = devAiResource.TenantId,
            };

            await resource.ArmCreateAsync(cancellationToken);

            return resource;
        }



        /// <summary>
        /// Creates the dependent resources for <see cref="BatchResource" />.
        /// </summary>
        /// <param name="instance">The resource instance in which the batch account is created.</param>
        /// <param name="sandbox">The resource sandbox if any in which the batch account is created.</param>
        /// <param name="keyVault">The instance's KeyVault resource.</param>
        /// <param name="appService">The instance's app service resource.</param>
        /// <param name="certificateBundles">The certificates for the instance.</param>
        /// <param name="metadataStorage">The instance's metadata storage account resource.</param>
        /// <param name="vNet">The instance's virtual network resource.</param>
        /// <param name="userAssignedManagedIdentity">The instance's user assigned managed identity resource.</param>
        /// <param name="globalUserAssignedManagedIdentity">The instance's global user assigned managed identity resource.</param>
        /// <param name="armAuthHelper">The <see cref="ArmAuthHelper" /> instance.</param>
        /// <param name="activeSlot">The current active slot in the instance.</param>
        public static BatchDependentResources CreateBatchDependentResources(UnversionedInstance instance, UnversionedSandbox sandbox, AppServiceResource appService, IEnumerable<CertificateBundle> certificateBundles, KeyVaultResource keyVault, StorageResource metadataStorage, VirtualNetworkResource vNet, UserAssignedManagedIdentityResource userAssignedManagedIdentity, UserAssignedManagedIdentityResource globalUserAssignedManagedIdentity, ArmAuthHelper armAuthHelper, string activeSlot) =>
            ArmResourceHelpers.CreateBatchDependentResources(appService, certificateBundles, instance.Properties.EnvironmentType, keyVault, metadataStorage, vNet, userAssignedManagedIdentity, globalUserAssignedManagedIdentity, new NamedMachinePool[] { sandbox?.Properties?.NamedSharedMachinePool ?? instance.Properties.NamedSharedMachinePool }, armAuthHelper, activeSlot);

        /// <summary>
        /// Creates the dependent resources for <see cref="BatchResource" />.
        /// </summary>
        /// <param name="keyVault">The instance's KeyVault resource.</param>
        /// <param name="appService">The instance's app service resource.</param>
        /// <param name="certificateBundles">The certificates for the instance.</param>
        /// <param name="environmentType">The environment type of the instance</param>
        /// <param name="metadataStorage">The instance's metadata storage account resource.</param>
        /// <param name="vNet">The instance's virtual network resource.</param>
        /// <param name="userAssignedManagedIdentity">The instance's user assigned managed identity resource.</param>
        /// <param name="globalUserAssignedManagedIdentity">The instance's global user assigned managed identity resource.</param>
        /// <param name="machinePools">The machines pools of the batch account.</param>
        /// <param name="armAuthHelper">The <see cref="ArmAuthHelper" /> instance.</param>
        /// <param name="activeSlot">The current active slot in the instance.</param>
        public static BatchDependentResources CreateBatchDependentResources(AppServiceResource appService, IEnumerable<CertificateBundle> certificateBundles, ResourceEnvironmentType environmentType, KeyVaultResource keyVault, StorageResource metadataStorage, VirtualNetworkResource vNet, UserAssignedManagedIdentityResource userAssignedManagedIdentity, UserAssignedManagedIdentityResource globalUserAssignedManagedIdentity, IEnumerable<NamedMachinePool> machinePools, ArmAuthHelper armAuthHelper, string activeSlot) => new BatchDependentResources()
        {
            ActiveSlot = activeSlot,
            AppService = appService,
            ArmAuthHelper = armAuthHelper,
            Certificates = certificateBundles,
            EnvironmentType = environmentType,
            KeyVault = keyVault,
            MachinePools = machinePools,
            MetadataStorageAccount = metadataStorage,
            VirtualNetwork = vNet,
            UserAssignedManagedIdentity = userAssignedManagedIdentity,
            GlobalUserAssignedManagedIdentity = globalUserAssignedManagedIdentity
        };

        /// <summary>
        /// Creates the Azure Data Factory resource for the Instance/Sandbox and connects it to the KeyVault, Metadata Storage Account, App Service, and Batch resources.
        /// </summary>
        /// <param name="logger">The logger to record the event.</param>
        /// <param name="accessToken">The access token to call to the ARM REST api.</param>
        /// <param name="instance">The resource instance in which the data factory is created.</param>
        /// <param name="sandbox">The resource sandbox if any in which the data factory is created.</param>
        /// <param name="keyVault">The instance's KeyVault resource.</param>
        /// <param name="metadataStorage">The instance's metadata storage account resource.</param>
        /// <param name="appService">The instance's app service resource.</param>
        /// <param name="batchAccount">The instance's batch account resource.</param>
        /// <param name="tags">The tags added to the data factory.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async Task<DataFactoryResource> CreateDataFactoryAsync(ILogger logger, AccessToken accessToken, UnversionedInstance instance, UnversionedSandbox sandbox, KeyVaultResource keyVault, StorageResource metadataStorage, AppServiceResource appService, BatchResource batchAccount, IDictionary<string, string> tags, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var session = new SessionLogger(
                logger: logger,
                sessionEventName: "adf/create",
                sessionMessage: string.Format(RPConstants.ArmManager.EventMessageCreateOrUpdateTemplate, RPConstants.ResourceTypes.DataFactory),
                globalProperties: new Dictionary<string, string>() {
                    {"key_vault_id", keyVault.Id },
                    {"metadata_storage_id", metadataStorage.Id },
                    {"batch_account_id", batchAccount.Id },
                    {"app_service_id", appService.Id }
                });

            try
            {
                var dataFactory = await ArmResourceHelpers.CreateArmResourceAsync<DataFactoryResource, Factory, DataFactoryDependentResources>(
                    (sandbox is not null) ? sandbox.Properties.InternalMetadata.AzureResources.DataFactory.Name : instance.Properties.InternalMetadata.AzureResources.DataFactory.Name,
                    accessToken,
                    instance,
                    logger,
                    tags,
                    new DataFactoryDependentResources()
                    {
                        AppService = appService,
                        BatchAccount = batchAccount,
                        Sandbox = sandbox,
                        KeyVault = keyVault,
                        SharedMachinePool = sandbox is null ? instance.Properties.NamedSharedMachinePool : sandbox.Properties.NamedSharedMachinePool,
                        MetadataStorageAccount = metadataStorage
                    },
                    cancellationToken: cancellationToken);
                ;

                session.Properties.Add("data_factory_id", dataFactory.Id);
                session.SetSessionSucceeded();

                return dataFactory;
            }
            catch (Exception ex)
            {
                session.SetSessionException(ex);
                throw;
            }
        }

        /// <summary>
        /// Creates the Azure Machine Learning resource for the Instance or the Sandbox and connects it to the KeyVault, Container Registry, and Metadata Storage Account resources.
        /// </summary>
        /// <param name="logger">The logger to record the event.</param>
        /// <param name="accessToken">The access token to call to the ARM REST api.</param>
        /// <param name="instance">The resource instance to which the Azure Machine Learning belongs.</param>
        /// <param name="sandbox">The resource to which the Azure Machine Learning belongs.</param>
        /// <param name="keyVault">The instance's Key Vault resource.</param>
        /// <param name="metadataStorage">The instance's metadata storage account resource.</param>
        /// <param name="registry">The instance's container registry resource.</param>
        /// <param name="tags">The tags to Azure Machine Learning.</param>
        /// <param name="userAssignedManagedIdentityResource">The Managed Identity resource</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async Task<MachineLearningResource> CreateMachineLearningAccountAsync(ILogger logger, AccessToken accessToken, UnversionedInstance instance, UnversionedSandbox sandbox, KeyVaultResource keyVault, StorageResource metadataStorage, ContainerRegistryResource registry, IDictionary<string, string> tags, UserAssignedManagedIdentityResource userAssignedManagedIdentityResource, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var amlName = (sandbox is null) ? instance.Properties.InternalMetadata.AzureResources.MachineLearning.Name : sandbox.Properties.InternalMetadata.AzureResources.MachineLearning.Name;

            using var session = new SessionLogger(
                logger: logger,
                sessionEventName: "aml/create",
                sessionMessage: string.Format(RPConstants.ArmManager.EventMessageCreateOrUpdateTemplate, RPConstants.ResourceTypes.MachineLearning),
                localProperties: new Dictionary<string, string>()
                {
                    { RPConstants.Telemetry.Property.ResourceName, amlName },
                },
                globalProperties: new Dictionary<string, string>() {
                    {"key_vault_id", keyVault.Id },
                    {"metadata_storage_id", metadataStorage.Id },
                    {"registry_id", registry.Id }
                });

            try
            {
                var aml = await ArmResourceHelpers.CreateArmResourceAsync<MachineLearningResource, AmlWorkspace, MachineLearningDependentResources>(
                    amlName,
                    accessToken,
                    instance,
                    logger,
                    tags,
                    new MachineLearningDependentResources()
                    {
                        ContainerRegistry = registry,
                        KeyVault = keyVault,
                        MetadataStorageAccount = metadataStorage,
                        UserAssignedManagedIdentityPrincipalId = userAssignedManagedIdentityResource.Instance.PrincipalId.Value.ToString()
                    },
                    cancellationToken: cancellationToken);

                session.Properties.Add("aml_id", aml.Id);
                session.SetSessionSucceeded();

                return aml;
            }
            catch (Exception ex)
            {
                session.SetSessionException(ex);
                throw;
            }
        }

        /// <summary>
        /// Creates or Updates the Private DNS zones for the instance.
        /// </summary>
        /// <param name="logger">The logger to record the event.</param>
        /// <param name="accessToken">The access token to call to the ARM REST api.</param>
        /// <param name="instance">The resource instance to which the private endpoint belongs.</param>
        /// <param name="sandbox">The resource sandbox to which the private endpoint belongs or null if not applicable.</param>
        /// <param name="vNet">The instance's virtual network resource.</param>
        /// <param name="privateDnsZones">The list of DNS zones to add the private endpoints to</param>
        /// <param name="batch">The batch resource the private endpoint will be targeting</param>
        /// <param name="tags">The tags for the private endpoint.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The private endpoint created</returns>
        public static async Task<IList<PrivateEndpointResource<BatchResource, BatchAccount, BatchDependentResources>>> CreateOrUpdatePrivateEndpointsBatchAsync(
            ILogger logger,
            AccessToken accessToken,
            UnversionedInstance instance,
            UnversionedSandbox sandbox,
            VirtualNetworkResource vNet,
            IEnumerable<PrivateDnsZoneResource> privateDnsZones,
            BatchResource batch,
            IDictionary<string, string> tags,
            CancellationToken cancellationToken
        )
        {
            var batchAccountEndpoint = ArmResourceHelpers.CreateOrUpdatePrivateEndpointResourceAsync<BatchResource, BatchAccount, BatchDependentResources>(
                logger: logger,
                accessToken: accessToken,
                instance: instance,
                sandbox: sandbox,
                vNet: vNet,
                privateDnsZones: new List<PrivateDnsZoneResource>()
                {
                    ArmResourceHelpers.GetPrivateDnsResourceByName(privateDnsZones, RPConstants.PrivateDnsZones.BatchAccountZone),
                },
                resource: batch,
                subResourceName: RPConstants.PrivateEndpointSubResources.BatchAccountSubResource,
                tags: tags,
                cancellationToken: cancellationToken
            );

            var batchManagmentEndpoint = ArmResourceHelpers.CreateOrUpdatePrivateEndpointResourceAsync<BatchResource, BatchAccount, BatchDependentResources>(
                logger: logger,
                accessToken: accessToken,
                instance: instance,
                sandbox: sandbox,
                vNet: vNet,
                privateDnsZones: new List<PrivateDnsZoneResource>()
                {
                    ArmResourceHelpers.GetPrivateDnsResourceByName(privateDnsZones, RPConstants.PrivateDnsZones.BatchAccountZone),
                },
                resource: batch,
                subResourceName: RPConstants.PrivateEndpointSubResources.BatchNodeManagmentSubResource,
                tags: tags,
                cancellationToken: cancellationToken
            );

            return new List<PrivateEndpointResource<BatchResource, BatchAccount, BatchDependentResources>>()
            {
                await batchAccountEndpoint,
                await batchManagmentEndpoint
            };
        }

        /// <summary>
        /// Creates or Updates the Private DNS zones for the instance.
        /// </summary>
        /// <param name="logger">The logger to record the event.</param>
        /// <param name="accessToken">The access token to call to the ARM REST api.</param>
        /// <param name="instance">The resource instance to which the private endpoint belongs.</param>
        /// <param name="sandbox">The resource sandbox to which the private endpoint belongs or null if not applicable.</param>
        /// <param name="vNet">The instance's virtual network resource.</param>
        /// <param name="privateDnsZones">The list of DNS zones to add the private endpoints to</param>
        /// <param name="resource">The resource the private endpoint is being added to</param>
        /// <param name="subResourceName">The subresource the private endpoint will be targeting</param>
        /// <param name="tags">The tags for the private endpoint.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The private endpoint created</returns>
        public static async Task<PrivateEndpointResource<TResource, TResult, TDependents>> CreateOrUpdatePrivateEndpointResourceAsync<TResource, TResult, TDependents>(
            ILogger logger,
            AccessToken accessToken,
            UnversionedInstance instance,
            UnversionedSandbox sandbox,
            VirtualNetworkResource vNet,
            IList<PrivateDnsZoneResource> privateDnsZones,
            TResource resource,
            string subResourceName,
            IDictionary<string, string> tags,
            CancellationToken cancellationToken
        ) where TResource : IArmResource<TResult, TDependents>, new() where TDependents : class
        {
            var endpointName = PrivateEndpointResource<TResource, TResult, TDependents>.GetFullEndpointName(resourceName: resource.Name, resourceType: resource.ResourceType, subResourceName: subResourceName);

            using var session = new SessionLogger(
                logger: logger,
                sessionEventName: "private_endpoint/create_or_update",
                sessionMessage: string.Format(RPConstants.ArmManager.EventMessageCreateOrUpdateTemplate, RPConstants.ResourceTypes.PrivateEndpoint),
                localProperties: new Dictionary<string, string>()
                {
                    { RPConstants.Telemetry.Property.ResourceName, endpointName }
                }
            );

            try
            {
                IPrivateEndpointAzureResources azureResources = sandbox is null ? instance.Properties.InternalMetadata.AzureResources : sandbox.Properties.InternalMetadata.AzureResources;
                var existingEndpointMetadata = azureResources.PrivateEndpoints.Where(endpoint => string.Equals(endpoint.Name, endpointName, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                PrivateEndpointResource<TResource, TResult, TDependents> privateEndpointResource;

                if (existingEndpointMetadata?.IsCreated == true)
                {
                    privateEndpointResource = await ArmResourceHelpers.UpdateArmResourceAsync<PrivateEndpointResource<TResource, TResult, TDependents>, PrivateEndpoint, PrivateEndpointDependentResources<TResource, TResult, TDependents>>(
                        endpointName,
                        accessToken,
                        instance,
                        logger,
                        tags,
                        new PrivateEndpointDependentResources<TResource, TResult, TDependents>()
                        {
                            VirtualNetwork = vNet,
                            Resource = resource,
                            SubResourceName = subResourceName,
                            DNSZones = privateDnsZones
                        },
                        cancellationToken: cancellationToken
                    );
                    existingEndpointMetadata.Id = privateEndpointResource.Id;
                }
                else
                {
                    privateEndpointResource = await ArmResourceHelpers.CreateArmResourceAsync<PrivateEndpointResource<TResource, TResult, TDependents>, PrivateEndpoint, PrivateEndpointDependentResources<TResource, TResult, TDependents>>(
                        endpointName,
                        accessToken,
                        instance,
                        logger,
                        tags,
                        new PrivateEndpointDependentResources<TResource, TResult, TDependents>()
                        {
                            VirtualNetwork = vNet,
                            Resource = resource,
                            SubResourceName = subResourceName,
                            DNSZones = privateDnsZones
                        },
                        cancellationToken: cancellationToken
                    );
                    azureResources.PrivateEndpoints = azureResources.PrivateEndpoints.Append(new AzureResource(endpointName) { Id = privateEndpointResource.Id });
                }

                session.SetSessionSucceeded();
                return privateEndpointResource;
            }
            catch (Exception e)
            {
                session.SetSessionException(e);
                throw;
            }
        }

        /// <summary>
        /// Delete the given resource.
        /// </summary>
        public static async Task DeleteResourceAsync(ResourceManagementClient client, string resourceId, CancellationToken cancellationToken)
        {
            var captureGroups = RPConstants.ResourceIds.ResourceIdRegex.Match(resourceId).Groups;
            var providerNamespace = captureGroups.GetValueOrDefault("provider")?.Value;
            var resourceTypeName = captureGroups.GetValueOrDefault("resourceType")?.Value;

            var resourceProvider = await client.Providers.GetAsync(providerNamespace, cancellationToken: cancellationToken);
            var resourceTypes = resourceProvider.ResourceTypes;
            var resourceType = resourceTypes.Where(u => string.Equals(u.ResourceType, resourceTypeName, StringComparison.InvariantCultureIgnoreCase));
            // Get latest api version for given resource. This avoids having to keep a dictionary of resourceType -> apiVersion and should be fine since only deleteById is used
            var apiVersion = resourceType.First().ApiVersions.First();

            await client.Resources.DeleteByIdAsync(resourceId, apiVersion, cancellationToken);
        }

        /// <summary>
        /// Delete the given resource.
        /// </summary>
        /// <param name="resourceId">The fully qualified resource id. e.g. subscriptions/beae888c-caf6-40cb-b740-76df12df36a5/resourceGroups/mahuang-test/providers/Microsoft.DevAI/instances/mahuang02</param>
        /// <param name="apiVersion">The api version used to call ARM endpoint.</param>
        /// <param name="tokenCredentials">The token to send in the Rest request.</param>
        /// <param name="logger">The logger.</param>
        /// <param name="waitForComplete">Whether this method waits until the resource doesn't exist anymore.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async Task DeleteResourceAsync(string resourceId, string apiVersion, TokenCredentials tokenCredentials, ILogger logger, bool waitForComplete, CancellationToken cancellationToken)
        {
            var captureGroups = RPConstants.ResourceIds.ResourceIdRegex.Match(resourceId).Groups;
            var providerNamespace = captureGroups.GetValueOrDefault("provider")?.Value;
            var resourceType = captureGroups.GetValueOrDefault("resourceType")?.Value;
            var resourceName = captureGroups.GetValueOrDefault("resourceName")?.Value;

            var uri = $"{Common.Configuration.RP.ArmEndpoint}{resourceId}?api-version={apiVersion}";
            var props = new Dictionary<string, string>()
            {
                { "uri", uri },
            };

            using var session = new SessionLogger(logger, $"delete/{resourceType}", $"Delete resource {providerNamespace}/{resourceType}/{resourceName}", localProperties: props);

            try
            {
                session.Log(message: "Delete resource via ARM REST API.");
                using var response = await SendDeleteAsync(_HttpClient, uri, tokenCredentials, cancellationToken);
                var responseStatusCode = response.StatusCode;

                // Return if the resource has already been deleted or cannot be found
                if (responseStatusCode == HttpStatusCode.NoContent)
                {
                    session.Log(message: "Resource not found or already deleted.");
                }
                else if (responseStatusCode != HttpStatusCode.OK && responseStatusCode != HttpStatusCode.Created && responseStatusCode != HttpStatusCode.Accepted)
                {
                    throw new ResourceNotDeletedException(resourceName, $"Unknown error: '{providerNamespace}/{resourceType}/{resourceName}' not deleted, error code: {responseStatusCode}. Details: {await response.Content.ReadAsStringAsync(cancellationToken)}");
                }
                else if (waitForComplete && responseStatusCode == HttpStatusCode.Accepted)
                {
                    var deletionCheckInterval = TimeSpan.FromSeconds(30);
                    var timeout = TimeSpan.FromMinutes(30);
                    using var timeoutCancellationTokenSource = new CancellationTokenSource(timeout);
                    using var linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCancellationTokenSource.Token);

                    // Resend the delete request while it's being deleted will cause Conflict response. We'll wait and check it again.
                    while (!linkedCancellationTokenSource.IsCancellationRequested && (responseStatusCode == HttpStatusCode.Conflict))
                    {
                        using var localResponse = await SendDeleteAsync(_HttpClient, uri, tokenCredentials, linkedCancellationTokenSource.Token);
                        responseStatusCode = localResponse.StatusCode;

                        if (responseStatusCode == HttpStatusCode.NoContent) // No content means the resource was deleted
                        {
                            session.Log(message: "Sucessfully deleted resource via ARM REST API.");
                            break;
                        }

                        await Task.Delay(deletionCheckInterval, linkedCancellationTokenSource.Token);
                    }

                    if (responseStatusCode != HttpStatusCode.NoContent)
                    {
                        throw new ResourceNotDeletedException(resourceName, "Resource may be deleted, but checks passed the timeout");
                    }
                }

                session.SetSessionSucceeded();
            }
            catch (Exception e)
            {
                session.SetSessionException(e);
                throw;
            }

            async Task<HttpResponseMessage> SendDeleteAsync(HttpClient httpClient, string uri, TokenCredentials tokenCredentials, CancellationToken cancellationToken)
            {
                using var httpRequestMessage = new HttpRequestMessage(HttpMethod.Delete, uri);
                var now = DateTime.UtcNow;
                httpRequestMessage.Headers.Add("x-ms-date", now.ToString("R", CultureInfo.InvariantCulture));
                httpRequestMessage.Headers.Add("x-ms-version", "2017-07-29");
                await tokenCredentials.ProcessHttpRequestAsync(httpRequestMessage, cancellationToken);

                return await httpClient.SendAsync(httpRequestMessage, cancellationToken);
            }
        }

        /// <summary>
        /// Helper function that gets an ArmResource with relevant context.
        /// </summary>
        /// <typeparam name="TResource">Type of resource wrapper to initialize.</typeparam>
        /// <typeparam name="TResult">Underlying resource type that the wrapper creates.</typeparam>
        /// <typeparam name="TDependents">The related resources associated with the resource wrapper.</typeparam>
        /// <param name="resourceName">Name of the resource to get.</param>
        /// <param name="accessToken">The access token needed to get the resource.</param>
        /// <param name="devAiResource">Context to get a resource from.</param>
        /// <param name="logger">The current <see cref="ILogger"/> instance in context.</param>
        /// <param name="relatedResources">Related resources to associate with the resource.</param>
        /// <param name="resourceGroupName">The name of the resource group to create a resource in. If not specified, <paramref name="devAiResource"/> resource group will be used.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Resource wrapper that was created.</returns>
        public static async Task<TResource> GetArmResourceAsync<TResource, TResult, TDependents>(string resourceName, AccessToken accessToken, BaseUnversionedResource devAiResource, ILogger logger, TDependents relatedResources = null, string resourceGroupName = null, CancellationToken cancellationToken = default)
            where TResource : IArmResource<TResult, TDependents>, new()
            where TDependents : class
        {
            var resource = new TResource
            {
                AccessToken = accessToken,
                Logger = logger,
                Name = resourceName,
                RegionName = devAiResource.Location,
                RelatedResources = relatedResources,
                ResourceGroupName = string.IsNullOrWhiteSpace(resourceGroupName) ? devAiResource.ResourceGroupName : resourceGroupName,
                SubscriptionId = devAiResource.SubscriptionId,
            };

            await resource.ArmGetAsync(cancellationToken);

            return resource;
        }

        /// <summary>
        /// Helper function that updates an ArmResource with relevant context.
        /// </summary>
        /// <typeparam name="TResource">Type of resource wrapper to initialize.</typeparam>
        /// <typeparam name="TResult">Underlying resource type that the wrapper creates.</typeparam>
        /// <typeparam name="TDependents">The related resources associated with the resource wrapper.</typeparam>
        /// <param name="resourceName">Name of the resource to create.</param>
        /// <param name="accessToken">The access token needed to create the resource.</param>
        /// <param name="instance">Context to update a resource in.</param>
        /// <param name="logger">The current <see cref="ILogger"/> instance in context.</param>
        /// <param name="tags">The tags added to the resource.</param>
        /// <param name="relatedResources">Related resources to associate with the resource.</param>
        /// <param name="resourceGroupName">The name of the resource group to create a resource in. If not specified, <paramref name="instance"/> resource group will be used.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Resource wrapper that was created.</returns>
        public static async Task<TResource> UpdateArmResourceAsync<TResource, TResult, TDependents>(string resourceName, AccessToken accessToken, UnversionedInstance instance, ILogger logger, IDictionary<string, string> tags, TDependents relatedResources = null, string resourceGroupName = null, CancellationToken cancellationToken = default)
            where TResource : IArmResource<TResult, TDependents>, new()
            where TDependents : class
        {
            var resource = new TResource
            {
                AccessToken = accessToken,
                Logger = logger,
                Name = resourceName,
                RegionName = instance.Location,
                RelatedResources = relatedResources,
                ResourceGroupName = string.IsNullOrWhiteSpace(resourceGroupName) ? instance.ResourceGroupName : resourceGroupName,
                SubscriptionId = instance.SubscriptionId,
                Tags = tags,
                TenantId = instance.Properties.InternalMetadata.TenantId,
            };

            await resource.ArmUpdateAsync(cancellationToken);

            return resource;
        }



        /// <summary>
        /// Adds the new machine pool to the collection or replace the existing one with the same name.
        /// </summary>
        /// <param name="machinePools">The machine pool collection. The collection isn't changed.</param>
        /// <param name="newMachinePool">The machine pool to add or replace.</param>
        /// <returns>A new collection with the new machine pool.</returns>
        private static IEnumerable<NamedMachinePool> AddOrReplaceMachinePool(IEnumerable<NamedMachinePool> machinePools, NamedMachinePool newMachinePool) =>
            machinePools.Where((p) => !string.Equals(p.Name, newMachinePool.Name, StringComparison.OrdinalIgnoreCase)).Append(newMachinePool);


        /// <summary>
        /// Will get the private dns zone from a list based on name
        /// </summary>
        /// <param name="privateDnsZones">The list of DNS zones</param>
        /// <param name="privateDnsZoneName">The name of the DNS zone you want to find</param>
        /// <returns>The private DNS zone with the name specified</returns>
        public static PrivateDnsZoneResource GetPrivateDnsResourceByName(IEnumerable<PrivateDnsZoneResource> privateDnsZones, string privateDnsZoneName) => privateDnsZones.First(zone => zone.Name == privateDnsZoneName);
    }
}
