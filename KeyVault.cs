using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using HackathonExamples;
using Microsoft.VisualBasic;
using System.Data.SqlTypes;
using System.Data.SqlClient;
using System.Data;

namespace HackathonExamples
{
    internal class KeyVault
    {

        public static void DoBunchOfThingsWithKey(SecureString key)
        {
            var queryPrefix = "prefix";
            using (var conn = new SqlConnection("readerConnectionString"))
            {
                using (var command = new SqlCommand(queryPrefix + key))
                {
                    try
                    {
                        var reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            Console.Write("Hello");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Write(ex.Message);
                        return;
                    }
                }
            }
        }

        public static void runSqlCommand(string input)
        {
            var command = new SqlCommand()
            {
                CommandText = "SELECT ProductId FROM Products WHERE ProductName = '" + input + "'",
                CommandType = CommandType.Text
            };
            var reader = command.ExecuteReader();
        }

        /// <summary>
        /// Creates the Azure Batch account for the Sandbox or the Instance and connects it to the KeyVault, Metadata Storage, VNet, and auth certificate resources.
        /// </summary>
        /// <param name="logger">The logger to record the event.</param>
        /// <param name="accessToken">The access token to call to the ARM REST api.</param>
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
        /// <param name="tags">The tags to the batch account.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async void CreateBatchAccountAsync(IDictionary<string, string> tags, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {

                var batchKey = FunctionalMethods.GetKeyAsync(cancellationToken: cancellationToken);
                DoBunchOfThingsWithKey(batchKey);
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
}
