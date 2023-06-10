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
using System.Globalization;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace HackathonExamples
{
    internal class KeyVault
    {
        public SqlConnection sqlConnection;
        public static void DoBunchOfThingsWithKey(SecureString key)
        {
            var queryPrefix = "prefix";
            var conn = new SqlConnection("readerConnectionString") ;
            var command = new SqlCommand(queryPrefix + key) ;
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


        public void UpdateDatabaseFirewallRuleByPrefix(string prefix, IEnumerable<string> ranges)
        {
            string sqlQuery = string.Empty;
            foreach (var range in ranges)
            {
                string mystring = "EXECUTE sp_set_database_firewall_rule @name=N'{0}', @start_ip_address='{1}', @end_ip_address='{2}'";
                sqlQuery += string.Format(CultureInfo.InvariantCulture, mystring) + " ";
            }

            var connection = new SqlConnection(this.sqlConnection.ConnectionString) ;
                connection.Open();
            var sqlCommand = connection.CreateCommand() ;
                string sqlCommandTemplate = @"DECLARE @TranName VARCHAR(20);  
												SELECT @TranName = 'DbFireWallRule'
												BEGIN TRANSACTION @TranName
                                                IF EXISTS(SELECT * FROM sys.database_firewall_rules WHERE name like '{0}%')
                                                BEGIN
                                                DECLARE @temporaryTable table (name varchar(50))
                                                DECLARE @rulename nvarchar(50)
                                                DECLARE @Counter INT
                                                insert into @temporaryTable
                                                SELECT name from sys.database_firewall_rules WHERE name like '{0}%'
                                                SELECT @Counter = count(*) from @temporaryTable
                                                while (@Counter > 0)
                                                BEGIN
	                                                SELECT @rulename = name from @temporaryTable	
	                                                EXECUTE sp_delete_database_firewall_rule @name = @rulename
	                                                delete from @temporaryTable where name = @rulename
	                                                SET @Counter = @Counter - 1	
                                                END                                                    
                                                END                                                 
                                                BEGIN
                                                {1}
                                                END
                                                COMMIT TRANSACTION @TranName";

                string sqlCommandQuery = string.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, prefix, sqlQuery);
                sqlCommand.CommandText = sqlCommandQuery;
                sqlCommand.CommandType = System.Data.CommandType.Text;

                sqlCommand.ExecuteNonQuery();

                connection.Close();

        }

        private bool TryUpdateSQLDbFirewallRules(HttpResponseMessage error, Guid tenantId, Guid azureSubscriptionId, string dbItemName)
        {
            List<string> existingFirewallRules = new List<string>() ;


            IEnumerable<string> firewallRulesToAdd = existingFirewallRules
                .Where(cr => !existingFirewallRules.Any());

            UpdateDatabaseFirewallRuleByPrefix(dbItemName, new List<string>());

            error = null;
            return true;
        }

        [HttpGet]
        public void UpdateSqlDBFirewallRules(Guid tenantId, Guid azureSubscriptionId, string topologyInstanceId)
        {
            try
            {
                HttpResponseMessage error = new HttpResponseMessage();
                TryUpdateSQLDbFirewallRules(error, new Guid(), new Guid(), topologyInstanceId);
            }
            finally
            {
                Console.Write("Finished");
            }
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
        public static void CreateBatchAccountAsync(IDictionary<string, string> tags, CancellationToken cancellationToken)
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