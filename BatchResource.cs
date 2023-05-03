// Copyright (C) Microsoft Corporation. All rights reserved.

using Microsoft.Azure.Management.Authorization.Models;
using Microsoft.Azure.Management.Batch;
using Microsoft.Azure.Management.Batch.Models;
using Microsoft.Azure.Management.Compute;
using Microsoft.Azure.Management.Compute.Models;
using Microsoft.Azure.Management.Network;
using Microsoft.Azure.Storage.Blob;
using Microsoft.DevAI.Core.Auth;
using Microsoft.DevAI.Core.Configuration;
using Microsoft.DevAI.Core.Exceptions;
using Microsoft.DevAI.Core.Storage;
using Microsoft.DevAI.Core.Storage.SharedAccessToken;
using Microsoft.DevAI.Logging;
using Microsoft.DevAI.ResourceProvider.API.Exceptions;
using Microsoft.DevAI.ResourceProvider.API.Helpers;
using Microsoft.DevAI.ResourceProvider.API.Models;
using Microsoft.DevAI.ResourceProvider.API.Models.Shared;
using Microsoft.DevAI.ResourceProvider.API.Models.Shared.MachinePools;
using Microsoft.DevAI.ResourceProvider.API.Resources.DependentResources;
using Microsoft.DevAI.Web;
using Microsoft.Extensions.Logging;
using Microsoft.Rest;
using Microsoft.Rest.Azure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using ImageReference = Microsoft.Azure.Management.Batch.Models.ImageReference;

namespace Microsoft.DevAI.ResourceProvider.API.Resources
{
    /// <summary>
    /// A wrapper for creating an Azure Batch resource.
    /// https://github.com/Azure-Samples/azure-batch-samples/blob/master/CSharp/AccountManagement/Program.cs
    /// </summary>
    public class BatchResource : ArmResource<BatchAccount, BatchDependentResources>, IDisposable
    {
        private const string _SmlCoreIdWindows = "SmlBatchApp";
        private const string _SmlCoreIdLinux = "SmlBatchAppLinux";
        private const string _AppPackagePrefixWindows = "%AZ_BATCH_APP_PACKAGE_";
        private const string _AppPackagePrefixLinux = "$AZ_BATCH_APP_PACKAGE_";
        private const string _FirstPartyStartTaskCmdWindows = _AppPackagePrefixWindows + _SmlCoreIdWindows + "%\\" + RPConstants.StartTaskCommandWindows;
        private const string _FirstPartyStartTaskCmdLinux = _AppPackagePrefixLinux + _SmlCoreIdLinux + "/" + RPConstants.StartTaskCommandLinux;

        private const string _ImageGalleryResourceGroup = "az-image-builder";
        private const string _ImageGalleryName = "az_image";
        private const string _ImageNameWindows = "azwinsvr";
        private const string _ImageNameLinux = "azubuntusvr";
        private const string _ImageReadyState = "Succeeded";

        private const string _CommandLineApplicationWindows = "cmd /c";
        private const string _CommandLineApplicationLinux = "/bin/bash -c";

        private const string _OsMetadataName = "OS";

        private const int _LongRunningOperationRetryTimeoutInSeconds = 300;
        private static readonly TimeSpan _BatchClientHttpTimeout = TimeSpan.FromMinutes(15);

        private static readonly HttpClient _HttpClient = new HttpClient();
        private BatchManagementClient _batchManagementClient;

        private BatchManagementClient ManagementClient
        {
            get
            {
                if (this._batchManagementClient is null)
                {
                    this._batchManagementClient = GetBatchManagementClient(this.AccessToken.Credentials, this.SubscriptionId);
                }

                return this._batchManagementClient;
            }
        }

        /// <summary>
        /// The name of the Azure ARM service that supplies this resources.
        /// </summary>
        public override string ProviderName => "Microsoft.Batch";

        /// <summary>
        /// The name of the type of resource that the <see cref="ProviderName"/> creates.
        /// </summary>
        public override string ResourceType => RPConstants.ResourceTypes.Batch;

        /// <inheritdoc />
        public void Dispose()
        {
            if (this._batchManagementClient is not null)
            {
                this._batchManagementClient.Dispose();
                this._batchManagementClient = null;
            }
        }

        /// <inheritdoc />
        public override async Task<BatchAccount> CreateAsync(CancellationToken cancellationToken)
        {
            var batchAccount = await this.ManagementClient.BatchAccount.CreateAsync(
                    this.ResourceGroupName,
                    this.Name,
                    new BatchAccountCreateParameters()
                    {
                        AutoStorage = new AutoStorageBaseProperties(this.RelatedResources.MetadataStorageAccount.Id),
                        Location = this.RegionName,
                        Tags = this.Tags
                    },
                    cancellationToken);

            var provisioningState = await RpHelpers.WaitForTerminatedProvisioningStateAsync(
                async () => (await this.ManagementClient.BatchAccount.GetAsync(this.ResourceGroupName, this.Name, cancellationToken)).ProvisioningState,
                provisioningWaitTimeSpan,
                cancellationToken
            );

            var logProperties = new Dictionary<string, string>
            {
                {"batch.account.id", this.Id },
                {"rbac.role.id", BuiltInRbacRoles.ContributorId },
                {"service.principal.id", this.RelatedResources.AppService.Instance.Identity.PrincipalId }
            };
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("rbac", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Grant the App Service Contributor access to the Batch Account", logProperties);
            await RbacHelpers.AddRoleAssignmentAsync(this.AccessToken, this.SubscriptionId, this.Id, BuiltInRbacRoles.ContributorId, this.RelatedResources.AppService.Instance.Identity.PrincipalId.ToLower(), PrincipalType.ServicePrincipal, cancellationToken);
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("rbac", ApiCoreConstants.Telemetry.Event.EndSuffix), "Grant the App Service Contributor access to the Batch Account", logProperties);

            return batchAccount;
        }

        /// <summary>
        /// Create or update pools in the batch account
        /// </summary>
        /// <param name="cancellationToken">The cancellation token</param>
        /// <returns>A task to be awaited</returns>
        public async Task CreateOrUpdatePoolsAsync(CancellationToken cancellationToken)
        {
            var targetSlot = this.RelatedResources.ActiveSlot != null ?
                (this.RelatedResources.ActiveSlot == RPConstants.SlotSuffixOne ? RPConstants.SlotSuffixTwo : RPConstants.SlotSuffixOne)
                : null;
            await this.ProcessPoolsAsync(cancellationToken, targetSlot);
        }

        /// <inheritdoc />
        public override async Task<BatchAccount> GetAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await this.ManagementClient.BatchAccount.GetAsync(this.ResourceGroupName, this.Name, cancellationToken);
        }

        /// <inheritdoc />
        public override async Task<BatchAccount> UpdateAsync(CancellationToken cancellationToken)
            => await this.ManagementClient.BatchAccount.GetAsync(this.ResourceGroupName, this.Name, cancellationToken);

        /// <summary>
        /// Checks if the resource name is available.
        /// </summary>
        /// <param name="credentials">The access token to use with Azure REST API.</param>
        /// <param name="subscriptionId">The target subscription id for the resource.</param>
        /// <param name="location">The name of the resource location.</param>
        /// <param name="resourceName">The name of the resource.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async Task<CheckNameAvailabilityResult> CheckNameAvailabilityAsync(TokenCredentials credentials, string subscriptionId, string location, string resourceName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var batchManagementClient = GetBatchManagementClient(credentials, subscriptionId);

            var result = await batchManagementClient.Location.CheckNameAvailabilityAsync(location, resourceName, cancellationToken: cancellationToken);

            return new CheckNameAvailabilityResult()
            {
                Message = result.Message,
                Reason = result.Reason?.ToString(),
                NameAvailable = result.NameAvailable == true
            };
        }

        /// <summary>
        /// Gets all the Pools in a Batch instance.
        /// </summary>
        /// <param name="subscriptionId">The subscription id which has the Batch account</param>
        /// <param name="resourceGroupName">The resource group name which has the Batch account</param>
        /// <param name="batchAccountName">The Batch account name</param>
        /// <param name="creds">The access token to use with Azure REST API.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async Task<IEnumerable<Pool>> GetPoolsAsync(string subscriptionId, string resourceGroupName, string batchAccountName, TokenCredentials creds, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var poolsList = new List<Pool>();
            using (var batchManagementClient = new BatchManagementClient(creds))
            {
                batchManagementClient.SubscriptionId = subscriptionId;

                var pools = await batchManagementClient.Pool.ListByBatchAccountAsync(resourceGroupName, batchAccountName, cancellationToken: cancellationToken);
                if (pools.Any())
                {
                    poolsList.AddRange(pools);

                    while (pools.NextPageLink != null)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        pools = await batchManagementClient.Pool.ListByBatchAccountNextAsync(pools.NextPageLink, cancellationToken);
                        poolsList.AddRange(pools);
                    }
                }
            }
            return poolsList;
        }

        /// <summary>
        /// Checks if there any overlaps between names for requested pools and currently provisioned pools
        /// </summary>
        /// <param name="requestedPools">The pools requested by the operation</param>
        /// <param name="existingPools">The subscription id which has the Batch account</param>
        public static IEnumerable<string> GetOverlappingPoolNames(IEnumerable<NamedMachinePool> requestedPools, IEnumerable<Pool> existingPools)
        {
            var existingPoolNames = existingPools.Select(u => u.Name);
            var requestedPoolNames = requestedPools.Select(u => u.Name);

            return existingPoolNames.Intersect(requestedPoolNames, StringComparer.InvariantCultureIgnoreCase); // overlap between requested names and existing names ignoring case
        }

        /// <summary>
        /// Gets an access key for the Batch account.
        /// </summary>
        /// <param name="getPrimaryKey">Indicates whether to retrieve the primary or secondary key.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        internal async Task<SecureString> GetKeyAsync(bool getPrimaryKey = true, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            SecureString value = null;

            var keys = await this.ManagementClient.BatchAccount.GetKeysAsync(this.ResourceGroupName, this.Name, cancellationToken);
            var key = getPrimaryKey ? keys.Primary : keys.Secondary;

            value = new SecureString();
            foreach (var c in key)
            {
                value.AppendChar(c);
            }

            return value;
        }

        /// <summary>
        /// Gets a Pool in this Batch instance by name.
        /// </summary>
        /// <param name="poolName">The name of the Pool to retrieve.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        internal async Task<Pool> GetPoolByNameAsync(string poolName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await this.ManagementClient.Pool.GetAsync(this.ResourceGroupName, this.Name, poolName, cancellationToken: cancellationToken);
            }
            catch (CloudException e) when (e.Response.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }
        }

        /// <summary>
        /// Deletes a Pool in this Batch instance by name.
        /// </summary>
        /// <param name="poolName">The name of the Pool to delete.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        internal async Task DeletePoolByNameAsync(string poolName, CancellationToken cancellationToken)
        {
            var logProperties = new Dictionary<string, string>
            {
                {"pool.name", poolName }
            };
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("pool", "delete", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Remove existing VM pool from the batch account.", logProperties);
            cancellationToken.ThrowIfCancellationRequested();
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("pool", "delete", "wait", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Waiting for Batch to remove existing VM pool.", logProperties);

            PoolDeleteHeaders poolDeleteHeaders;
            while ((poolDeleteHeaders = await this.ManagementClient.Pool.DeleteAsync(this.ResourceGroupName, this.Name, poolName, cancellationToken)).Location != null)
            {
                var retryAfter = poolDeleteHeaders.RetryAfter ?? 1;
                await Task.Delay(retryAfter * 1000, cancellationToken);
            }
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("pool", "delete", "wait", ApiCoreConstants.Telemetry.Event.EndSuffix), "Waiting for Batch to remove existing VM pool.", logProperties);


            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("pool", "delete", ApiCoreConstants.Telemetry.Event.EndSuffix), "Remove existing VM pool from the batch account.", logProperties);
        }

        /// <summary>
        /// For adding applications to an azure batch pool.
        /// </summary>
        /// <param name="apps">The applications to be added</param>
        /// <param name="pool">The pool to add the application to.</param>
        public static bool TryAddApplicationsToBatchPool(IEnumerable<Application> apps, Pool pool)
        {
            var updated = false;
            foreach (var app in apps)
            {
                var appPackRef = new ApplicationPackageReference()
                {
                    Id = app.Id,
                    Version = app.DefaultVersion
                };

                if (pool.ApplicationPackages != null)
                {
                    var existingAppPackRef = pool.ApplicationPackages.FirstOrDefault(app => appPackRef.Id.ToLowerInvariant() == app.Id.ToLowerInvariant());
                    if (existingAppPackRef != null)
                    {
                        if (appPackRef.Version != existingAppPackRef.Version)
                        {
                            existingAppPackRef.Version = appPackRef.Version;
                            updated = true;
                        }
                    }
                    else
                    {
                        pool.ApplicationPackages.Add(appPackRef);
                        updated = true;
                    }
                }
                else
                {
                    pool.ApplicationPackages = new List<ApplicationPackageReference>() { appPackRef };
                    updated = true;
                }
            }

            return updated;
        }

        /// <summary>
        /// An overload for AddApplicationsAsync specifically for adding 3rd party batch applications.
        /// </summary>
        /// <param name="app">The associated batch pool app.</param>
        /// <param name="keyVaultName">The name of the key vault resource.</param>
        /// <param name="storageAccountName">The name of the metadata storage resource.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public Task<Application> AddApplicationAsync(MachinePoolApp app, string keyVaultName, string storageAccountName, CancellationToken cancellationToken)
            => this.AddApplicationAsync(RPConstants.Containers.ReleasesStore, app.Store, app.Name, app.FileName, keyVaultName, storageAccountName, cancellationToken);

        /// <summary>
        /// Adds an application to the Batch account.
        /// </summary>
        /// <param name="containerName">The name of the blob container that holds the application.</param>
        /// <param name="containerDirectory">The name of the root directory in the container that holds the application.</param>
        /// <param name="applicationName">The name of the application to add.</param>
        /// <param name="applicationBlobName">The name of the zip file in Blob Storage containing the application.</param>
        /// <param name="keyVaultName">The name of the key vault resource.</param>
        /// <param name="storageAccountName">The name of the metadata storage resource.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task<Application> AddApplicationAsync(string containerName, string containerDirectory,
            string applicationName, string applicationBlobName, string keyVaultName, string storageAccountName, CancellationToken cancellationToken)
        {
            var logProperties = new Dictionary<string, string>
            {
                {"container.name", containerName },
                {"container.directory", containerDirectory },
                {"application.name", applicationName },
                {"application.blob.name", applicationBlobName },
                {"kev.vault.name", keyVaultName },
                {"storage.name", storageAccountName },
            };

            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Add or update application in batch account.", logProperties);
            cancellationToken.ThrowIfCancellationRequested();

            var storageHelper = new StorageHelper(this.RelatedResources.ArmAuthHelper, keyVaultName, Common.SecretNames.MetadataStorageKey);
            var sasProvider = new SasTokenProvider(storageHelper);
            var blobPrefix = await storageHelper.GetLatestVersionOfBlobAsync(storageAccountName, containerName, containerDirectory, cancellationToken);
            var appPackageVersion = blobPrefix.Split('/')[1];
            var appPackageUri = await sasProvider.GetBlobSasUriAsync(storageAccountName, containerName, $"{blobPrefix}{applicationBlobName}", expiryTimeMinutes: 30);

            logProperties.Add("blob.prefix", blobPrefix);
            logProperties.Add("app.package.version", appPackageVersion);
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "package", "create", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Create application in batch account.", logProperties);
            var appPackage = await this.ManagementClient.ApplicationPackage.CreateAsync(this.ResourceGroupName, this.Name, applicationName, appPackageVersion, cancellationToken);
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "package", "create", ApiCoreConstants.Telemetry.Event.EndSuffix), "Create application in batch account.", logProperties);

            var blob = new CloudBlockBlob(new Uri(appPackage.StorageUrl));

            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "download", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Download latest published application.", logProperties);
            var httpResult = await _HttpClient.GetAsync(appPackageUri, cancellationToken);
            var data = await httpResult.Content.ReadAsByteArrayAsync(cancellationToken);
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "download", ApiCoreConstants.Telemetry.Event.EndSuffix), "Download latest published application.", logProperties);
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "upload", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Upload application to Batch application storage location.", logProperties);
            using var stream = new MemoryStream(data);
            await blob.UploadFromStreamAsync(stream, cancellationToken);
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "upload", ApiCoreConstants.Telemetry.Event.EndSuffix), "Upload application to Batch application storage location.", logProperties);

            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "package", "activate", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Activate application in Batch account.", logProperties);
            await this.ManagementClient.ApplicationPackage.ActivateAsync(this.ResourceGroupName, this.Name, applicationName, appPackageVersion, RPConstants.DefaultAppFormat, cancellationToken);
            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "package", "activate", ApiCoreConstants.Telemetry.Event.EndSuffix), "Activate application in Batch account.", logProperties);

            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "create", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Create application in batch account.", logProperties);
            var app = await this.ManagementClient.Application.CreateAsync(
                    this.ResourceGroupName,
                    this.Name,
                    applicationName,
                    new Application()
                    {
                        AllowUpdates = true,
                        DefaultVersion = appPackageVersion,
                        DisplayName = applicationName,
                    },
                    cancellationToken);

            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("app", "create", ApiCoreConstants.Telemetry.Event.EndSuffix), "Create application in batch account.", logProperties);

            return app;
        }

        /// <summary>
        /// Adds or updates a machine pool to the Batch account. For update, the existing configuration is copied where appropriate to retain
        /// configuration changes made outside of the instance creation / update scenario, such as Experiment apps.
        /// </summary>
        /// <param name="batchPool">The <see cref="MachinePool"/> specifying the pool's properties.</param>
        /// <param name="slot">The slot instance of the Pool.</param>
        /// <param name="imageId">The full resource id for the image to use.</param>
        /// <param name="applications">The applications to deploy on the VMs within the pool.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task<Pool> AddOrUpdatePoolAsync(NamedMachinePool batchPool, string slot, string imageId, IEnumerable<Application> applications, CancellationToken cancellationToken)
        {
            var poolName = RpHelpers.GetBatchSlotName(batchPool.Name, slot);
            var logProperties = new Dictionary<string, string>
            {
                {"batch.pool", JsonConvert.SerializeObject(batchPool) },
                {"slot", slot },
                {"image.id", imageId },
                {"applications", JsonConvert.SerializeObject(applications) },
            };

            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("pool", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Add or update VM pool on the batch account.", logProperties);
            cancellationToken.ThrowIfCancellationRequested();

            var parameters = await this.GetNewPoolParameters(batchPool, imageId, applications, cancellationToken);

            var existingPool = await this.GetPoolByNameAsync(poolName, cancellationToken);
            if (existingPool != null)
            {
                logProperties.Add("existing.image.id", existingPool.DeploymentConfiguration.VirtualMachineConfiguration.ImageReference.Id);
                logProperties.Add("existing.applications", JsonConvert.SerializeObject(existingPool.ApplicationPackages));
                await this.DeletePoolByNameAsync(poolName, cancellationToken);
                MergeExistingPoolApplications(parameters.ApplicationPackages, existingPool.ApplicationPackages);
            }

            try
            {

                var pool = await this.ManagementClient.Pool.CreateAsync(this.ResourceGroupName, this.Name, poolName, parameters, cancellationToken: cancellationToken);
                this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("pool", ApiCoreConstants.Telemetry.Event.EndSuffix), "Add or update VM pool on the batch account.", logProperties);
                return pool;
            }
            catch (CloudException ex)
            {
                var formattedException = new ResourceNotCreatedException(poolName, ex.Message, ex);
                this.Logger.Log(
                    LogLevel.Error,
                    message: $"Failed to create VM pool with error: {formattedException.Message}.",
                    exception: formattedException,
                    properties: logProperties
                );
                throw formattedException;
            }

        }

        private async Task<Pool> GetNewPoolParameters(MachinePool batchPool, string imageId, IEnumerable<Application> applications, CancellationToken cancellationToken)
        {
            // for now, we only let the Key Vault VM extension monitor Geneva certificate since KV VM extension for Windows doesn't support defining certificate store location per certificate and Geneva cert is the only cert currently gets installed into LocalMachine
            // we can move other certificates to be installed under LocalMachine but the KV VM extesnsion grants access to the private key of the certificate only to the local system admin account and we can't run as admin through ADF
            // so our activities won't have access to the certficate private key. They are working on a solution to close this feature gap.
            // please see https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/key-vault-windows#property-values
            var genevaCertificate = this.RelatedResources.Certificates.Where(c => c.CertificateIdentifier.Name.Contains("Geneva", StringComparison.OrdinalIgnoreCase));

            // Currently we do not read any certificates from Linux nodes.
            // If this changes in the future, please ensure that we are using the KeyVault Extension to download the certificate
            // and not the Azure Batch certificates (they are not automatically rotated).
            // Currently Linux certificates are not accessible to Batch activity users once they are rotated, due to permissions.
            // please see https://devdiv.visualstudio.com/OnlineServices/_workitems/edit/1619093
            var observedCertificates = genevaCertificate.Select(c => $"https://{this.RelatedResources.KeyVault.Name}.vault.azure.net/secrets/{c.CertificateIdentifier.Name}");

            var secretsManagementSettings = new
            {
                pollingIntervalInS = "3600",
                certificateStoreName = "My", //ignored on linux
                linkOnRenewal = batchPool.VmOsType == OsType.Windows, //only Windows
                certificateStoreLocation = batchPool.VmOsType == OsType.Windows ? "LocalMachine" : AuthConstants.LinuxCertificatesPath,
                requireInitialSync = false,
                observedCertificates
            };

            var vmExtensionSettings = new
            {
                secretsManagementSettings = secretsManagementSettings,
                authenticationSettings = new
                {
                    msiEndpoint = "http://169.254.169.254/metadata/identity",
                    msiClientId = this.RelatedResources.UserAssignedManagedIdentity.Instance.ClientId
                }
            };

            var userAssignedIdentities = new Dictionary<string, UserAssignedIdentities>
            {
                [this.RelatedResources.UserAssignedManagedIdentity.Id] =
                            new UserAssignedIdentities()
            };

            if (this.RelatedResources.GlobalUserAssignedManagedIdentity != null)
            {
                userAssignedIdentities[this.RelatedResources.GlobalUserAssignedManagedIdentity.Id] =
                            new UserAssignedIdentities();
            }

            return new Pool()
            {
                ApplicationPackages = await this.GetApplicationReferences(applications, batchPool.Apps, cancellationToken),
                DeploymentConfiguration = new DeploymentConfiguration()
                {
                    VirtualMachineConfiguration = new VirtualMachineConfiguration()
                    {
                        ImageReference = new ImageReference()
                        {
                            Id = imageId
                        },
                        NodeAgentSkuId = GetNodeAgentSkuId(batchPool.VmOsType),
                        // VM disk encryption is not supported for custom images on linux so only encrypt on windows for now.
                        DiskEncryptionConfiguration = batchPool.VmOsType == OsType.Windows ? new DiskEncryptionConfiguration(targets: new List<DiskEncryptionTarget> { DiskEncryptionTarget.OsDisk, DiskEncryptionTarget.TemporaryDisk }) : null,
                        Extensions = new List<VMExtension>()
                        {
                            new VMExtension()
                            {
                                Name = "KeyVaultVMExt",
                                Type = batchPool.VmOsType == OsType.Windows ? "KeyVaultForWindows" : "KeyVaultForLinux",
                                Publisher = "Microsoft.Azure.KeyVault",
                                TypeHandlerVersion = "1.0",
                                AutoUpgradeMinorVersion = true,
                                Settings = JObject.Parse(JsonConvert.SerializeObject(vmExtensionSettings))
                            }
                        }
                    }
                },
                Identity = new BatchPoolIdentity
                {
                    Type = PoolIdentityType.UserAssigned,
                    UserAssignedIdentities = userAssignedIdentities
                },
                InterNodeCommunication = InterNodeCommunicationState.Disabled,
                NetworkConfiguration = new NetworkConfiguration()
                {
                    SubnetId = this.RelatedResources.VirtualNetwork.GetSubnetId(RPConstants.BatchSubnet),
                    PublicIPAddressConfiguration = new PublicIPAddressConfiguration()
                    {
                        Provision = IPAddressProvisioningType.NoPublicIPAddresses
                    }
                },
                TaskSlotsPerNode = batchPool.MaxTasksPerNode,
                TargetNodeCommunicationMode = NodeCommunicationMode.Simplified,
                ScaleSettings = GetScaleSettings(batchPool.Scale),
                StartTask = GetPoolStartTask(this.RelatedResources.EnvironmentType, batchPool, string.Join('.', this.Name, genevaCertificate.FirstOrDefault().CertificateIdentifier.Name)),
                Metadata = new List<MetadataItem>()
                {
                    new MetadataItem(_OsMetadataName, batchPool.VmOsType.ToString())
                    },
                    TaskSchedulingPolicy = new TaskSchedulingPolicy()
                    {
                        NodeFillType = ComputeNodeFillType.Spread
                    },
                    VmSize = batchPool.VmSize,
                };
        }

        /// <summary>
        /// Gets an ApplicationPackageReference for each of the applications created within this batch account instance as well as any 3rd party applications specific to a VM Pool.
        /// </summary>
        /// <param name="firstPartyApps">The first party applications within this Batch instance.</param>
        /// <param name="thirdPartyApps">The third party applications within this Pool instance.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task<IList<ApplicationPackageReference>> GetApplicationReferences(IEnumerable<Application> firstPartyApps, IEnumerable<MachinePoolApp> thirdPartyApps, CancellationToken cancellationToken)
        {
            var appRefs = new List<ApplicationPackageReference>();
            foreach (var app in firstPartyApps)
            {
                appRefs.Add(new ApplicationPackageReference()
                {
                    Id = app.Id,
                    Version = app.DefaultVersion
                });
            }

            if (thirdPartyApps != null)
            {
                foreach (var app in thirdPartyApps)
                {
                    var batchApp = await this.AddApplicationAsync(RPConstants.Containers.ReleasesStore, app.Store, app.Name, app.FileName,
                        this.RelatedResources.KeyVault.Name, this.RelatedResources.MetadataStorageAccount.Name, cancellationToken);

                    appRefs.Add(new ApplicationPackageReference()
                    {
                        Id = batchApp.Id,
                        Version = batchApp.DefaultVersion
                    });
                }
            }

            return appRefs;
        }

        /// <summary>
        /// Gets the latest version of the image available in the Shared Image Gallery based on the
        /// request's subscription and region.
        /// </summary>
        /// <param name="imagePlatform">The platform to use when getting the correct image.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        internal async Task<string> GetLatestImageVersion(OsType imagePlatform, CancellationToken cancellationToken)
        {
            var imageName = GetImageName(imagePlatform);
            var logProperties = new Dictionary<string, string>
            {
                {"image.gallery.resource.group", _ImageGalleryResourceGroup },
                {"image.gallery.name", _ImageGalleryName },
                {"image.name", imageName }
            };

            this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("image", ApiCoreConstants.Telemetry.Event.BeginSuffix), "Get latest version of batch VM image.", logProperties);
            cancellationToken.ThrowIfCancellationRequested();

            var imageVersions = new List<GalleryImageVersion>();
            using (var managementClient = new ComputeManagementClient(this.AccessToken.Credentials) { SubscriptionId = this.SubscriptionId })
            {
                var versions = await managementClient.GalleryImageVersions.ListByGalleryImageAsync(_ImageGalleryResourceGroup, _ImageGalleryName, imageName, cancellationToken);
                if (versions.Any())
                {
                    var readyVersions = versions.Where(version => version.ProvisioningState == _ImageReadyState);
                    imageVersions.AddRange(readyVersions);

                    while (versions.NextPageLink != null)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        versions = await managementClient.GalleryImageVersions.ListByGalleryImageNextAsync(versions.NextPageLink, cancellationToken);
                        readyVersions = versions.Where(version => version.ProvisioningState == _ImageReadyState);
                        imageVersions.AddRange(readyVersions);
                    }
                }
            }

            if (imageVersions.Any())
            {
                var image = imageVersions.OrderByDescending(image => image.Name).First();
                logProperties.Add("image.id", image.Id);
                logProperties.Add("image.version", image.Name);
                this.Logger.Log(LogLevel.Information, LoggerHelper.JoinEventNames("image", ApiCoreConstants.Telemetry.Event.EndSuffix), "Get latest version of batch VM image.", logProperties);

                return image.Id;
            }

            throw new ResourceNotFoundException(imageName, "os_images", $"Shared Image Gallery {_ImageGalleryName} has no available versions of image {imageName} in region {this.RegionName} for subscription {this.SubscriptionId}.");
        }

        /// <summary>
        /// Gets the full command set to run as part of the start-up tasks for the 1stParty App.
        /// </summary>
        /// <param name="environmentType">The environment used to log telemetry</param>
        /// <param name="oSPlatform">The OS Platform type used in the batch pool</param>
        /// <param name="genevaCertificateName">The name of the certificate used to authenticate to Geneva</param>
        private static string GetFirstPartyStartTaskCommand(ResourceEnvironmentType environmentType, OsType oSPlatform, string genevaCertificateName)
        {
            if (oSPlatform == OsType.Windows)
            {
                var genevaConfiguration = GenevaResourceConfiguration.GetConfigurationForEnvironment(environmentType);
                return $"{_FirstPartyStartTaskCmdWindows} {genevaConfiguration.MonitoringGCSAccount} {genevaConfiguration.MonitoringWindowsVMConfigVersion} {genevaConfiguration.MonitoringGCSAuthId}";
            }
            else if (oSPlatform == OsType.Linux)
            {
                var genevaConfiguration = GenevaResourceConfiguration.GetConfigurationForEnvironment(environmentType);
                return $"'{_FirstPartyStartTaskCmdLinux} {genevaConfiguration.MonitoringGCSAccount} {genevaConfiguration.MonitoringLinuxVMConfigVersion} {genevaConfiguration.MonitoringGCSAuthId} {genevaCertificateName}'";
            }
            else
            {
                // This should never happen since we are validating Resource request parameters
                throw new ArgumentException($"{oSPlatform} is not a supported platform type.");
            }
        }

        /// <summary>
        /// Gets an instance of the batch management client.
        /// </summary>
        /// <param name="creds">Token credentials for initializing client.</param>
        /// <param name="subscriptionId">The subscription id for the client.</param>
        /// <returns></returns>
        internal static BatchManagementClient GetBatchManagementClient(TokenCredentials creds, string subscriptionId)
        {
            var batchManagementClient = new BatchManagementClient(creds)
            {
                SubscriptionId = subscriptionId,
                LongRunningOperationRetryTimeout = _LongRunningOperationRetryTimeoutInSeconds
            };
            batchManagementClient.HttpClient.Timeout = _BatchClientHttpTimeout;

            return batchManagementClient;
        }

        /// <summary>
        /// Updates the pools start tasks according to the batch application parameters.
        /// </summary>
        /// <param name="batchApps">The batch pool apps.</param>
        /// <param name="pool">The pool who's start task will be updated.</param>
        public static void UpdateBatchPoolStartTask(IEnumerable<MachinePoolApp> batchApps, Pool pool)
        {
            // Get the Pool OS configuration from the pool metadata
            var osPlatform = (OsType)Enum.Parse(typeof(OsType), pool.Metadata.Where(item => item.Name == _OsMetadataName).FirstOrDefault().Value);
            var newCommands = GetThirdPartyStartTaskCommand(batchApps, osPlatform);

            // Check if the command for the new or updated app. If we're only updating the app
            // then we don't need to update the command.
            if (!pool.StartTask.CommandLine.Contains(newCommands))
            {
                pool.StartTask.CommandLine = $"{pool.StartTask.CommandLine}{newCommands}";
            }
        }

        /// <summary>
        /// Gets the full command set to run as part of the start-up tasks.
        /// </summary>
        /// <param name="apps">The set of 3rd party apps to be installed in the pool.</param>
        /// <param name="oSPlatform">The OS platform type the pool is configured to</param>
        private static string GetThirdPartyStartTaskCommand(IEnumerable<MachinePoolApp> apps, OsType oSPlatform)
        {
            var command = string.Empty;
            var startTaskCommand = (oSPlatform == OsType.Windows) ? RPConstants.StartTaskCommandWindows : RPConstants.StartTaskCommandLinux;
            var commandPrefix = (oSPlatform == OsType.Windows) ? $" && %AZ_BATCH_APP_PACKAGE_" : $" && $AZ_BATCH_APP_PACKAGE_";
            var commandSuffix = (oSPlatform == OsType.Windows) ? $"%\\{startTaskCommand}" : $"/{startTaskCommand}";

            if (apps != null)
            {
                foreach (var app in apps)
                {
                    if (app.StartTaskStatus == Status.Enabled)
                    {
                        command += $"{commandPrefix}{app.Name}{commandSuffix}";
                    }
                }
            }

            return command;
        }

        /// <summary>
        /// Gets the Batch Scale Settings from the requested definition.
        /// </summary>
        /// <param name="scale"></param>
        /// <returns></returns>
        private static ScaleSettings GetScaleSettings(MachinePoolScale scale)
        {
            if (scale.Mode == MachinePoolScaleMode.Auto)
            {
                return new ScaleSettings()
                {
                    AutoScale = new AutoScaleSettings()
                    {
                        EvaluationInterval = TimeSpan.FromMinutes(scale.EvaluationPeriodMinutes),
                        Formula = scale.Formula
                    }
                };
            }

            return new ScaleSettings()
            {
                FixedScale = new FixedScaleSettings()
                {
                    TargetDedicatedNodes = scale.DedicatedNodeCount
                }
            };
        }

        /// <summary>
        /// Gets a CertificateReference for each of the certificates created within this batch account instance.
        /// </summary>
        /// <param name="certificates">The certificates within this instance.</param>
        /// <param name="osPlatform">The OS platform the pool using the certificates is configured for.</param>
        private static IList<CertificateReference> GetCertificateReferences(IEnumerable<(Certificate, bool)> certificates, OsType osPlatform)
        {
            var certRefs = new List<CertificateReference>();
            foreach ((var cert, var isGenevaCert) in certificates)
            {
                var certReference = GetCertificateReference(cert, isGenevaCert, osPlatform);
                certRefs.Add(certReference);
            }

            return certRefs;
        }

        /// <summary>
        /// Gets a CertificateReference for a specified certificate.
        /// </summary>
        /// <param name="cert">The certificate to get the reference for.</param>
        /// <param name="isGenevaCert">flag indicating if a geneva certificate is being passed in.</param>
        /// <param name="osPlatform">The OS platform the pool using the certificates is configured for.</param>
        /// <returns>A certificate reference for the input certificate</returns>
        public static CertificateReference GetCertificateReference(Certificate cert, bool isGenevaCert, OsType osPlatform)
        {
            CertificateStoreLocation location;
            if (isGenevaCert && osPlatform == OsType.Windows)
            {
                location = CertificateStoreLocation.LocalMachine;
            }
            else
            {
                // Linux cannot store certificates in LocalMachine store on batch.
                location = CertificateStoreLocation.CurrentUser;
            }

            return new CertificateReference()
            {
                Id = cert.Id,
                StoreLocation = location,
                StoreName = "My",
                Visibility = new List<CertificateVisibility>()
                        {
                            CertificateVisibility.RemoteUser,
                            CertificateVisibility.StartTask,
                            CertificateVisibility.Task
                        }
            };
        }

        /// <summary>
        /// A helper method that adds or updates pools specified in the request.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <param name="targetSlot">The target slot of the pool to add or update. If none is provided both slots will be updated.</param>
        internal async Task ProcessPoolsAsync(CancellationToken cancellationToken, string targetSlot = null)
        {
            var batchPools = this.RelatedResources.MachinePools;

            foreach (var batchPool in batchPools)
            {
                var appName = batchPool.VmOsType == OsType.Windows ? _SmlCoreIdWindows : _SmlCoreIdLinux;
                var blobName = batchPool.VmOsType == OsType.Windows ? RPConstants.Blobs.SmlCoreWindows : RPConstants.Blobs.SmlCoreLinux;
                var apps = new List<Application>
                {
                    await this.AddApplicationAsync(RPConstants.Containers.Releases, RPConstants.Blobs.CorePrefix, appName, blobName,
                        this.RelatedResources.KeyVault.Name, this.RelatedResources.MetadataStorageAccount.Name, cancellationToken)
                };

                var latestImageVersion = await this.GetLatestImageVersion(batchPool.VmOsType, cancellationToken);

                if (string.IsNullOrEmpty(targetSlot))
                {
                    await this.AddOrUpdatePoolAsync(batchPool, RPConstants.SlotSuffixOne, latestImageVersion, apps, cancellationToken);
                    await this.AddOrUpdatePoolAsync(batchPool, RPConstants.SlotSuffixTwo, latestImageVersion, apps, cancellationToken);
                }
                else
                {
                    await this.AddOrUpdatePoolAsync(batchPool, targetSlot, latestImageVersion, apps, cancellationToken);
                }
            }
        }

        /// <summary>
        /// Adds application packages from the existingApplicationPackages that are not already included in the applicationPackages list by comparing their id (name).
        /// applicationPackages can contain new application packages or more commonly newer versions of the application packages that we want to include in the pool.
        /// </summary>
        /// <param name="applicationPackages">The list of application packages with the latest version.</param>
        /// <param name="existingApplicationPackages">The list of application packages with their version included in the existing pool.</param>
        private static void MergeExistingPoolApplications(IList<ApplicationPackageReference> applicationPackages, IList<ApplicationPackageReference> existingApplicationPackages)
        {
            foreach (var existingAppPackage in existingApplicationPackages)
            {
                if (!applicationPackages.Any(ap => ap.Id.Equals(existingAppPackage.Id, StringComparison.InvariantCultureIgnoreCase)))
                {
                    applicationPackages.Add(existingAppPackage);
                }
            }
        }

        /// <summary>
        /// Gets the Image name to use when creating a pool based on the requested OS Platform type.
        /// </summary>
        /// <param name="oSPlatform">The request OS Platform type for the pool.</param>
        /// <returns>A string representing the name of the image to use when creating a pool.</returns>
        private static string GetImageName(OsType oSPlatform) => (oSPlatform == OsType.Windows) ? _ImageNameWindows : _ImageNameLinux;

        /// <summary>
        /// Gets the Sku Id to use when creating a pool based on the requested OS Platform type.
        /// </summary>
        /// <param name="oSPlatform">The request OS Platform type for the pool.</param>
        /// <returns>A string representing the Sku Id to use when creating a pool.</returns>
        private static string GetNodeAgentSkuId(OsType oSPlatform) => (oSPlatform == OsType.Windows) ? "batch.node.windows amd64" : "batch.node.ubuntu 18.04";

        /// <summary>
        /// Gets the start task for a specific OS pool configuration.
        /// </summary>
        /// <param name="environmentType">The environment to use in the start task command.</param>
        /// <param name="batchPool">The batch pool to set this start task for.</param>
        /// <param name="genevaCertificateName">The name of the certificate used to authenticate to Geneva</param>
        /// <returns>A <see cref="StartTask"/> for a specific OS pool configuration</returns>
        private static StartTask GetPoolStartTask(ResourceEnvironmentType environmentType, MachinePool batchPool, string genevaCertificateName)
        {
            string commandLineApplication;
            var resourceFile = new ResourceFile(autoStorageContainerName: RPConstants.Containers.Configuration, blobPrefix: RPConstants.Blobs.InstanceConfiguration);

            if (batchPool.VmOsType == OsType.Windows)
            {
                commandLineApplication = _CommandLineApplicationWindows;
            }
            else if (batchPool.VmOsType == OsType.Linux)
            {
                commandLineApplication = _CommandLineApplicationLinux;
                resourceFile.FilePath = "../../shared/";
                resourceFile.FileMode = "0444";
            }
            else
            {
                // This should never happen since we are validating Resource request parameters
                throw new ArgumentException($"{batchPool.VmOsType} is not a supported platform type.");
            }

            var commandLine = $"{commandLineApplication} {GetFirstPartyStartTaskCommand(environmentType, batchPool.VmOsType, genevaCertificateName)} {GetThirdPartyStartTaskCommand(batchPool.Apps, batchPool.VmOsType)}";

            var startTask = new StartTask()
            {
                CommandLine = commandLine,
                MaxTaskRetryCount = 1,
                UserIdentity = new UserIdentity()
                {
                    AutoUser = new AutoUserSpecification()
                    {
                        ElevationLevel = ElevationLevel.Admin,
                        Scope = AutoUserScope.Pool
                    }
                },
                ResourceFiles = new List<ResourceFile>()
                {
                    resourceFile
                },
                WaitForSuccess = true
            };

            return startTask;
        }
    }
}
