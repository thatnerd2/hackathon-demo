namespace Microsoft.DynamicsOnline.Deployment.Service.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Data;
    using System.Data.SqlClient;
    using System.Diagnostics.CodeAnalysis;
    using System.Diagnostics.Contracts;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using Library.Model;
    using Microsoft.DynamicsOnline.Deployment.DataModel.Manifest;
    using Microsoft.DynamicsOnline.Deployment.ObjectModel;
    using Microsoft.DynamicsOnline.Deployment.Service.Engine.Tasks;
    using Microsoft.DynamicsOnline.Deployment.Service.Engine.Tasks.ArtifactManagement;
    using static Microsoft.DynamicsOnline.Deployment.Service.Engine.AzureSQLDatabaseDeploymentWorkflow;

    /// <summary>
    /// This class is used to execute T-SQL to perform database operations.
    /// This paradigm is used since all these operations aren't exposed as API's.
    /// </summary>
    public class DatabaseOperations
    {
        /// <summary>
        /// The max length of the database name.
        /// </summary>
        public const int DatabaseNameMaxLength = 50;

        /// <summary>
        /// Master database Name.
        /// </summary>
        public const string MasterDbName = "master";

        /// <summary>
        /// The name patter for firewall rules.
        /// </summary>
        private const string RuleNamePattern = "^[0-9a-zA-Z-_]+$";

        /// <summary>
        /// The pattern for user names.
        /// </summary>
        private const string UserNamePattern = "^[0-9a-zA-Z]+$";

        /// <summary>
        /// The patter for role names.
        /// </summary>
        private const string RoleNamePattern = "^[0-9a-zA-Z-_]+$";

        /// <summary>
        /// The patter for passwords. NEED to VALIDATE ^[0-9a-zA-Z-_]+$";.
        /// </summary>
        private const string PasswordPattern = "";

        /// <summary>
        /// The connection string builder for connecting to target DB.
        /// </summary>
        private SqlConnectionStringBuilder sqlConnection = new SqlConnectionStringBuilder();

        /// <summary>
        /// Initializes a new instance of the DatabaseOperations class.
        /// </summary>
        /// <param name="serverFQDN">Fully qualified server name.</param>
        /// <param name="databaseName">Database name for the connection.</param>
        /// <param name="userName">User name for the connection.</param>
        /// <param name="password">Password for the connection.</param>
        public DatabaseOperations(string serverFQDN, string databaseName, string userName, string password)
        {
            Contract.Requires(!String.IsNullOrEmpty(serverFQDN));
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(!String.IsNullOrEmpty(userName));
            Contract.Requires(!String.IsNullOrEmpty(password));

            this.sqlConnection.DataSource = serverFQDN;
            this.sqlConnection.InitialCatalog = databaseName;
            this.sqlConnection.UserID = userName;
            this.sqlConnection.Password = CommonHelper.GetKeyVaultSecret(password);
            this.sqlConnection.Encrypt = true;
            this.sqlConnection.TrustServerCertificate = false;
            this.sqlConnection.ConnectRetryCount = 3;
            this.sqlConnection.ConnectRetryInterval = 5;
            this.sqlConnection.ConnectTimeout = 60;
        }

        /// <summary>
        /// Defines the different SQL Replication Roles a database could be.
        /// </summary>
        private enum SqlRole
        {
            /// <summary>
            /// This indicated the SQL Role is the primary database.
            /// </summary>
            Primary = 0,

            /// <summary>
            /// This indicates the SQL Role is a secondary database.
            /// </summary>
            Secondary = 1,

            /// <summary>
            /// Unknown Role type.
            /// </summary>
            Unknown
        }

        /// <summary>
        /// Create or update a database user.
        /// </summary>
        /// <param name="dbuserName">User name to create.</param>
        /// <param name="dbuserPassword">Password for the user.</param>
        /// <param name="loginName">The login to associate user with.</param>
        public void CreateUpdateDatabaseUser(string dbuserName, string dbuserPassword, string loginName)
        {
            Contract.Requires(!String.IsNullOrEmpty(dbuserName));
            Contract.Requires(Regex.IsMatch(dbuserName, UserNamePattern));
            Contract.Requires(loginName == null ? !String.IsNullOrEmpty(dbuserPassword) : true);

            dbuserPassword = CommonHelper.GetKeyVaultSecret(dbuserPassword);
            Contract.Assert(Regex.IsMatch(dbuserPassword, PasswordPattern));

            string sqlCommandTemplate;
            string sqlCommand;
            if (loginName == null)
            {
                sqlCommandTemplate = @"IF NOT EXISTS(SELECT name FROM sys.database_principals WHERE name = '{0}' AND TYPE = 'S')
                                                BEGIN
                                                    CREATE USER [{0}] WITH PASSWORD='{1}'
                                                END
                                                ELSE    
                                                BEGIN
                                                    ALTER USER [{0}] WITH PASSWORD='{1}'
                                                END;";

                sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, dbuserName, dbuserPassword);
            }
            else
            {
                sqlCommandTemplate = @"IF NOT EXISTS(SELECT name FROM sys.database_principals WHERE name = '{0}' AND TYPE = 'S')
                                                BEGIN
                                                    CREATE USER [{0}] FOR LOGIN [{1}]
                                                END;";

                sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, dbuserName, loginName);
            }

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Adds Application id to Database and assigns db owner role to the app name.
        /// </summary>
        /// <param name="applicationName">The application name.</param>
        /// <param name="applicationId">The application id.</param>
        public void AddAppIdAsOwnerToDatabase(string applicationName, string applicationId)
        {
            Contract.Requires(!String.IsNullOrEmpty(applicationName));
            Contract.Requires(!String.IsNullOrEmpty(applicationId));

            string applicationIdinOctet = CommonHelper.ConvertGuidToOctetString(applicationId);

            string sqlCommandTemplate = @"if not exists(select 1 from sys.database_principals where name = '{0}' or sid = {1})
                                        BEGIN
                                        CREATE USER [{0}] WITH SID = {1}, TYPE = E
                                        END;";
            string sqlCommand = string.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, applicationName, applicationIdinOctet);
            this.ExecuteSQLCommand(sqlCommand);

            sqlCommandTemplate = "exec sp_addrolemember N'db_owner', '{0}'";
            sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, applicationName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Adds Application id to Database and assigns dbmanager role to the app name.
        /// </summary>
        /// <param name="applicationName">The application name.</param>
        /// <param name="applicationId">The application id.</param>
        public void AddAppIdAsDbManagerToDatabase(string applicationName, string applicationId)
        {
            Contract.Requires(!String.IsNullOrEmpty(applicationName));
            Contract.Requires(!String.IsNullOrEmpty(applicationId));

            string applicationIdinOctet = CommonHelper.ConvertGuidToOctetString(applicationId);

            string sqlCommandTemplate = @"if not exists(select 1 from sys.database_principals where name = '{0}' or sid = {1})
                                        BEGIN
                                        CREATE USER [{0}] WITH SID = {1}, TYPE = E
                                        END;";
            string sqlCommand = string.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, applicationName, applicationIdinOctet);
            this.ExecuteSQLCommand(sqlCommand);

            sqlCommandTemplate = "exec sp_addrolemember N'dbmanager', '{0}'";
            sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, applicationName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Adds Application id to Database and assigns db owner role to the app name.
        /// </summary>
        /// <param name="applicationName">The application name.</param>
        /// <param name="applicationId">The application id.</param>
        public void AddAppIdAsReaderToDatabase(string applicationName, string applicationId)
        {
            Contract.Requires(!String.IsNullOrEmpty(applicationName));
            Contract.Requires(!String.IsNullOrEmpty(applicationId));

            string applicationIdinOctet = CommonHelper.ConvertGuidToOctetString(applicationId);

            string sqlCommandTemplate = @"if not exists(select 1 from sys.database_principals where name = '{0}' or sid = {1})
                                        BEGIN
                                        CREATE USER [{0}] WITH SID = {1}, TYPE = E
                                        END;";
            string sqlCommand = string.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, applicationName, applicationIdinOctet);
            this.ExecuteSQLCommand(sqlCommand);

            sqlCommandTemplate = "exec sp_addrolemember N'db_datareader', '{0}'";
            sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, applicationName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Create a database user for login with default schema.
        /// </summary>
        /// <param name="dbuserName">User name to create.</param>
        /// <param name="loginName">The login to associate user with.</param>
        public void CreateDatabaseUserForLoginWithDefaultSchema(string dbuserName, string loginName)
        {
            Contract.Requires(!String.IsNullOrEmpty(dbuserName));
            Contract.Requires(Regex.IsMatch(dbuserName, UserNamePattern));

            string sqlCommandTemplate;
            string sqlCommand;

            sqlCommandTemplate = @"IF NOT EXISTS(SELECT name FROM sys.database_principals WHERE name = '{0}' AND TYPE = 'S')
                                                BEGIN
                                                    CREATE USER [{0}] FOR LOGIN [{1}] WITH DEFAULT_SCHEMA = [dbo]
                                                END;";

            sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, dbuserName, loginName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Delete a given user from the database.
        /// </summary>
        /// <param name="dbuserName">User name to delete.</param>
        public void DeleteDatabaseUser(string dbuserName)
        {
            Contract.Requires(!String.IsNullOrEmpty(dbuserName));
            Contract.Requires(Regex.IsMatch(dbuserName, UserNamePattern));

            const string SqlCommandTemplate = @"IF EXISTS(SELECT name FROM sys.database_principals WHERE name = '{0}' AND TYPE = 'S')
                                                BEGIN
                                                    DROP USER [{1}]
                                                END;";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, dbuserName, dbuserName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Create a new role in the database.
        /// </summary>
        /// <param name="roleName">The name of the role.</param>
        /// <param name="priviledges">The privileges of the role.</param>        
        public void CreateRole(string roleName, string priviledges)
        {
            Contract.Requires(!String.IsNullOrEmpty(roleName));
            Contract.Requires(!String.IsNullOrEmpty(priviledges));
            Contract.Requires(Regex.IsMatch(roleName, RoleNamePattern));

            string sqlCommandTemplate = @"IF NOT EXISTS(SELECT name FROM sys.database_principals WHERE name = '{0}' AND TYPE = 'R')
                                                BEGIN
                                                    CREATE ROLE [{1}]
                                                END;";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, roleName, roleName);
            this.ExecuteSQLCommand(sqlCommand);

            sqlCommandTemplate = "GRANT {0} TO [{1}]";
            sqlCommand = String.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, priviledges, roleName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Add a user to a given database role.
        /// </summary>
        /// <param name="roleName">Role name.</param>
        /// <param name="dbuserName">User name to add to the Role.</param>
        public void AddRoleToUser(string roleName, string dbuserName)
        {
            Contract.Requires(!String.IsNullOrEmpty(roleName));
            Contract.Requires(!String.IsNullOrEmpty(dbuserName));
            Contract.Requires(Regex.IsMatch(roleName, RoleNamePattern));
            Contract.Requires(Regex.IsMatch(dbuserName, UserNamePattern));

            const string SqlCommandTemplate = @"IF IS_ROLEMEMBER('{0}', '{1}') = 0
                                                BEGIN
                                                    ALTER ROLE [{2}] ADD MEMBER [{3}]
                                                END;";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, roleName, dbuserName, roleName, dbuserName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Deletes a user from a database role association.
        /// </summary>
        /// <param name="roleName">Role name.</param>
        /// <param name="dbuserName">User name to remove from the Role.</param>
        public void DeleteRoleFromUser(string roleName, string dbuserName)
        {
            Contract.Requires(!String.IsNullOrEmpty(roleName));
            Contract.Requires(!String.IsNullOrEmpty(dbuserName));
            Contract.Requires(Regex.IsMatch(roleName, RoleNamePattern));
            Contract.Requires(Regex.IsMatch(dbuserName, UserNamePattern));

            const string SqlCommandTemplate = @"IF IS_ROLEMEMBER('{0}', '{1}') = 1
                                                BEGIN
                                                    ALTER ROLE [{2}] DROP MEMBER [{3}]
                                                END;";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, roleName, dbuserName, roleName, dbuserName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Adds an IP range to a database firewall rule table.
        /// </summary>
        /// <param name="ruleName">Rule name to add.</param>
        /// <param name="startIPaddress">Starting IP address.</param>
        /// <param name="endIPaddress">Ending IP address.</param>
        public void CreateDatabaseFirewallRule(string ruleName, string startIPaddress, string endIPaddress)
        {
            Contract.Requires(!String.IsNullOrEmpty(ruleName));
            Contract.Requires(!String.IsNullOrEmpty(startIPaddress));
            Contract.Requires(!String.IsNullOrEmpty(endIPaddress));
            Contract.Requires(Regex.IsMatch(ruleName, RoleNamePattern));

            const string SqlCommandTemplate = "EXECUTE sp_set_database_firewall_rule @name=N'{0}', @start_ip_address='{1}', @end_ip_address='{2}'";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, ruleName, startIPaddress, endIPaddress);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Creates or updates Database firewall rules.
        /// </summary>
        /// <param name="prefix">The sql rule prefix.</param>
        /// <param name="ranges">The ranges.</param>
        public void UpdateDatabaseFirewallRuleByPrefix(string prefix, IEnumerable<FirewallIPRange> ranges)
        {
            string sqlQuery = string.Empty;
            foreach (var range in ranges)
            {
                string sqlCommandTemplate = "EXECUTE sp_set_database_firewall_rule @name=N'{0}', @start_ip_address='{1}', @end_ip_address='{2}'";
                sqlQuery += string.Format(CultureInfo.InvariantCulture, sqlCommandTemplate, range.RulePrefix, range.StartIP, range.EndIP) + " ";
            }

            using (var connection = new SqlConnection(this.sqlConnection.ConnectionString))
            {
                connection.Open();

                using (var sqlCommand = connection.CreateCommand())
                {
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

            }
        }

        /// <summary>
        /// Removes a rule from the database firewall rule table.
        /// </summary>
        /// <param name="ruleName">Rule name to remove.</param>
        public void DeleteDatabaseFirewallRule(string ruleName)
        {
            Contract.Requires(!String.IsNullOrEmpty(ruleName));
            Contract.Requires(Regex.IsMatch(ruleName, RoleNamePattern));

            const string SqlCommandTemplate = "EXECUTE sp_delete_database_firewall_rule @name=N'{0}'";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, ruleName);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Gets the database-level firewall rules.
        /// </summary>
        /// <returns>A list of firewall rules in tuple-form, Item1 being the firewall rule name, Item2 being the start IP address,
        /// and Item3 being the end IP address.</returns>
        public IEnumerable<Azure.Management.Sql.Models.FirewallRule> GetDatabaseFirewallRules()
        {
            List<Azure.Management.Sql.Models.FirewallRule> firewallRules = new List<Azure.Management.Sql.Models.FirewallRule>();

            const string SqlCommandTemplate = "SELECT * FROM sys.database_firewall_rules";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate);

            using (DataTable dataTable = this.ExecuteSQLQuery(sqlCommand))
            {
                foreach (DataRow row in dataTable.Rows)
                {
                    Azure.Management.Sql.Models.FirewallRule rule = new Azure.Management.Sql.Models.FirewallRule((string)row[2], (string)row[3], name: (string)row[1]);
                    firewallRules.Add(rule);
                }
            }

            return firewallRules;
        }

        /// <summary>
        /// Creates or updates a Azure SQL server login.
        /// </summary>
        /// <param name="loginName">The name of the login.</param>
        /// <param name="loginPassword">The password for the login.</param>
        public void CreateUpdateLogin(string loginName, string loginPassword)
        {
            Contract.Requires(!String.IsNullOrEmpty(loginName));
            Contract.Requires(!String.IsNullOrEmpty(loginPassword));
            Contract.Requires(Regex.IsMatch(loginName, UserNamePattern));

            loginPassword = CommonHelper.GetKeyVaultSecret(loginPassword);
            Contract.Assert(Regex.IsMatch(loginPassword, PasswordPattern));

            const string SqlCommandTemplate = @"IF NOT EXISTS(SELECT name FROM sys.sql_logins WHERE name = '{0}')
                                                BEGIN
                                                    CREATE LOGIN [{0}] WITH PASSWORD='{1}'
                                                END
                                                ELSE    
                                                BEGIN
                                                    ALTER LOGIN [{0}] WITH PASSWORD='{1}'
                                                END;";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, loginName, loginPassword);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Creates the login on the given database.
        /// </summary>
        /// <param name="loginName">The login name.</param>
        /// <param name="loginPassword">The login password.</param>
        /// <param name="sid">The login sid.</param>
        public void CreateUpdateLogin(string loginName, string loginPassword, string sid)
        {
            const string SqlCommandTemplate = @"IF NOT EXISTS(SELECT name FROM sys.sql_logins WHERE name = '{0}')
                                                BEGIN
                                                    CREATE LOGIN [{0}] 
                                                    WITH PASSWORD='{1}',
                                                         SID = {2}
                                                END
                                                ELSE
                                                BEGIN
                                                    ALTER LOGIN [{0}]
                                                    WITH PASSWORD='{1}'
                                                END";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, loginName, loginPassword, sid);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Gets all logins on the given database.
        /// </summary>
        /// <returns>A list of logins in tuple-form, Item1 being the login name, Item2 being the sid.</returns>
        public IEnumerable<SqlLogin> GetLogins()
        {
            const string SqlCommand = @"SELECT [name], master.dbo.fn_varbintohexstr([sid])
                                        FROM [sys].[sql_logins] 
                                        WHERE [type_desc] = 'SQL_Login'";

            var logins = new List<SqlLogin>();

            using (DataTable dataTable = this.ExecuteSQLQuery(SqlCommand))
            {
                foreach (DataRow row in dataTable.Rows)
                {
                    logins.Add(new SqlLogin()
                    {
                        Name = (string)row[0],
                        Sid = (string)row[1],
                    });
                }
            }

            return logins;
        }

        /// <summary>
        /// Copies a database between subscriptions.
        /// </summary>
        /// <param name="sourceServer">The source Azure SQL server name.</param>
        /// <param name="sourceDatabaseName">The source Azure SQL database name.</param>        
        /// <param name="targetDatabaseName">The target Azure SQL database name.</param>
        public void CopyDatabaseAcrossSubscription(string sourceServer, string sourceDatabaseName, string targetDatabaseName)
        {
            Contract.Requires(!String.IsNullOrEmpty(sourceServer));
            Contract.Requires(!String.IsNullOrEmpty(sourceDatabaseName));
            Contract.Requires(sourceDatabaseName.Length < DatabaseNameMaxLength);
            Contract.Requires(!String.IsNullOrEmpty(targetDatabaseName));
            Contract.Requires(targetDatabaseName.Length < DatabaseNameMaxLength);

            const string SqlCommandTemplate = "CREATE DATABASE [{0}] AS COPY OF [{1}].[{2}]";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, targetDatabaseName, sourceServer, sourceDatabaseName);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Enable Change Tracking for a database. This command needs to be executed on the MASTER DB.
        /// </summary>
        /// <param name="databaseName">The target database for enabling change tracking.</param>
        /// <param name="retention">The retention value to set.</param>
        public void EnableChangeTracking(string databaseName, int retention)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            const string SqlCommandTemplate = @"IF EXISTS(SELECT database_id FROM sys.change_tracking_databases WHERE 
                                                                        database_id = (SELECT dbid FROM sys.sysdatabases WHERE name = '{0}'))
                                                BEGIN
                                                    ALTER DATABASE [{0}] SET CHANGE_TRACKING (CHANGE_RETENTION = {1} DAYS, AUTO_CLEANUP = ON);
                                                END;
                                                ELSE
                                                BEGIN
                                                    ALTER DATABASE [{0}] SET CHANGE_TRACKING = ON (CHANGE_RETENTION = {1} DAYS, AUTO_CLEANUP = ON);
                                                END";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, databaseName, retention);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Enable sql servers inbuilt data encryption capability.
        /// </summary>
        /// <param name="databaseName">The target database for enabling data encryption.</param>
        public void EnableTransparentDataEncryption(string databaseName)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            const string SqlCommandTemplate = "ALTER DATABASE [{0}] SET ENCRYPTION ON;";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, databaseName);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Sets the compatibility level of a SQL Database.
        /// </summary>
        /// <param name="databaseName">The target database for setting compatibility level.</param>
        /// <param name="level">The target database compatibility level.</param>
        public void SetDatabaseCompatibilityLevel(string databaseName, int level)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            const string SqlCommandTemplate = "ALTER DATABASE [{0}] SET COMPATIBILITY_LEVEL = {1};";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, databaseName, level);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Sets the compatibility level of a SQL Database.
        /// </summary>
        /// <param name="maxdop">The target database maxdop setting.</param>        
        public void SetMaxDegreeOfParallelism(int maxdop)
        {
            this.SetMaxDegreeOfParallelism(maxdop, forSecondary: false);
        }

        /// <summary>
        /// Sets the compatibility level of a SQL Database.
        /// </summary>
        /// <param name="maxdop">The target database maxdop setting.</param>
        /// <param name="forSecondary">Indicates that the setting should be applied to secondary databases.</param>
        public void SetMaxDegreeOfParallelism(int maxdop, bool forSecondary)
        {
            const string SqlCommandTemplate = @"ALTER DATABASE SCOPED CONFIGURATION {1} SET MAXDOP = {0}";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, maxdop, forSecondary ? "FOR SECONDARY" : String.Empty);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Enables or disables legacy cardinality estimation for SQL Database.
        /// </summary>
        /// <param name="enable">Indicated if parameter should be enabled or disabled.</param>
        public void SetLegacyCardinalityEstimation(bool enable)
        {
            this.SetDatabaseScopedFlag("LEGACY_CARDINALITY_ESTIMATION", enable);
        }

        /// <summary>
        /// Enables or disables parameter sniffing for SQL Database.
        /// </summary>
        /// <param name="enable">Indicated if parameter should be enabled or disabled.</param>
        public void SetParameterSniffing(bool enable)
        {
            this.SetDatabaseScopedFlag("PARAMETER_SNIFFING", enable);
        }

        /// <summary>
        /// Enables or disables query optimizer hot-fixes for SQL Database.
        /// </summary>
        /// <param name="enable">Indicated if parameter should be enabled or disabled.</param>
        public void SetEnableQueryOptimizerHotfixesg(bool enable)
        {
            this.SetDatabaseScopedFlag("QUERY_OPTIMIZER_HOTFIXES", enable);
        }

        /// <summary>
        /// Rename database if it exists.
        /// </summary>
        /// <param name="existingName">The existing database name.</param>
        /// <param name="newName">New name for the database if it exists.</param>
        public void RenameDatabase(string existingName, string newName)
        {
            Contract.Requires(!String.IsNullOrEmpty(existingName));
            Contract.Requires(!String.IsNullOrEmpty(newName));
            Contract.Requires(newName.Length < DatabaseNameMaxLength);

            string SqlCommandTemplate = @"IF EXISTS(SELECT name FROM SYS.DATABASES WHERE NAME = @ExistingName)
                                                BEGIN
                                                    ALTER DATABASE [{0}] MODIFY NAME = [@NewName];
                                                END;";

            SqlParameter sqlParameter1 = new SqlParameter("@ExistingName", SqlDbType.NVarChar);
            sqlParameter1.Value = existingName;
            SqlParameter sqlParameter2 = new SqlParameter("@NewName", SqlDbType.NVarChar);
            sqlParameter2.Value = newName;

            SqlParameter[] sqlParameters = new SqlParameter[] { sqlParameter1, sqlParameter2 };
            this.ExecuteSQLCommand(SqlCommandTemplate, sqlParameters);
        }

        /// <summary>
        /// Sets the ALLOW_SNAPSHOT_ISOLATION of a SQL Database ON or OFF.
        /// </summary>
        /// <param name="databaseName">The target database name.</param>
        /// <param name="enable">Indicates if read committed snapshot isolation enabled or disabled.</param>
        public void SetAllowSnapshotIsolation(string databaseName, bool enable)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            this.SetDatabaseSetting(databaseName, "ALLOW_SNAPSHOT_ISOLATION", enable ? "ON" : "OFF");
        }

        /// <summary>
        /// Sets the READ_COMMITTED_SNAPSHOT of a SQL Database ON or OFF.
        /// </summary>
        /// <param name="databaseName">The target database name.</param>
        /// <param name="enable">Indicates if read committed snapshot should be enabled or disabled.</param>
        public void SetReadCommittedSnapshot(string databaseName, bool enable)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            this.SetDatabaseSetting(databaseName, "READ_COMMITTED_SNAPSHOT", enable ? "ON" : "OFF");
        }

        /// <summary>
        /// Sets the QUERY_STORE of a SQL Database ON or OFF.
        /// </summary>
        /// <param name="databaseName">The target database name.</param>
        /// <param name="enable">The flag indicating if query store should be enabled or disabled.</param>
        /// <param name="queryStoreSettings">The additional settings for query store.</param>
        public void SetEnableQueryStore(string databaseName, bool enable, string queryStoreSettings)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            string queryStoreEnableStatement = "= ON";

            if (!String.IsNullOrWhiteSpace(queryStoreSettings))
            {
                queryStoreEnableStatement = String.Join(" ", queryStoreEnableStatement, queryStoreSettings);
            }

            this.SetDatabaseSetting(databaseName, "QUERY_STORE", enable ? queryStoreEnableStatement : "= OFF");
        }

        /// <summary>
        /// Initiates the Database failover and provides the option to specify if it was planned or not.
        /// </summary>
        /// <param name="databaseName">The name of the Database to fail over.</param>
        /// <param name="force">If this flag is set to true then the database will immediately promote the
        /// Secondary to Primary and any pending transactions are lost.</param>
        public void InitiateDatabaseFailover(string databaseName, bool force)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            RetryManager.ExecuteWithRetry(() =>
            {
                SqlRole role = this.GetGeoReplicationRole(databaseName);
                if (role == SqlRole.Primary)
                {
                    return true;
                }

                string sqlCommand = force ? string.Format(CultureInfo.InvariantCulture, "ALTER DATABASE [{0}] FORCE_FAILOVER_ALLOW_DATA_LOSS;", databaseName)
                    : string.Format(CultureInfo.InvariantCulture, "ALTER DATABASE [{0}] FAILOVER;", databaseName);

                this.ExecuteSQLCommand(sqlCommand);

                return true;
            });
        }

        /// <summary>
        /// Creates a new database on specified SQL Server.
        /// </summary>
        /// <param name="databaseName">The Name of the database to create.</param>
        /// <param name="edition">The SQL Edition to use i.e. Basic, Standard or Premium.</param>
        /// <param name="serviceObjective">The Service Objective Name i.e. B, S0-S3, or P1-P15.</param>
        /// <param name="collation">The collation settings for the Database. If null is specified then the default is used.</param>
        public void CreateDatabase(string databaseName, string edition, string serviceObjective, string collation)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(!String.IsNullOrEmpty(edition));
            Contract.Requires(!String.IsNullOrEmpty(serviceObjective));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            TimeSpan createDatabaseTimeout = TimeSpan.FromMinutes(2);
            IEnumerable<string> databaseNames = this.ListDatabaseNames();

            // Check that the SQL Database does not exist already.
            if (databaseNames.Contains(databaseName))
            {
                return;
            }

            StringBuilder builder = new StringBuilder();

            builder.AppendLine(string.Format(CultureInfo.InvariantCulture, "CREATE DATABASE [{0}]", databaseName));

            if (collation != null)
            {
                builder.AppendLine(string.Format(CultureInfo.InvariantCulture, "COLLATE {0}", collation));
            }

            builder.AppendFormat(CultureInfo.InvariantCulture, "(EDITION = '{0}', SERVICE_OBJECTIVE = '{1}');", edition, serviceObjective);

            RetryManager.ExecuteWithRetry(() =>
            {
                // Check that the SQL Database exist now, Usually the initial call fails
                // with a SQL Timeout and then the 2nd call fails because the database already exist.
                if (databaseNames.Contains(databaseName))
                {
                    return true;
                }

                string sqlCommand = builder.ToString();

                this.ExecuteSQLCommand(sqlCommand, createDatabaseTimeout);

                return true;
            });
        }

        /// <summary>
        /// Deletes the specified database from the SQL Server.
        /// </summary>
        /// <param name="databaseName">The name of the Database.</param>
        public void DeleteDatabase(string databaseName)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));

            IEnumerable<string> databaseNames = this.ListDatabaseNames();

            // Check that the SQL Database does not exist already.
            if (!databaseNames.Contains(databaseName))
            {
                return;
            }

            string sqlCommand = string.Format(CultureInfo.InvariantCulture, "DROP DATABASE [{0}]", databaseName);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Update the flag to reload the PBI data.
        /// </summary>
        public void AXUpdatePBIReportConfigFlag()
        {
            string sqlCommand = @"IF EXISTS(SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'PBIEMBEDDEDREPORTCONFIG')
                                BEGIN
                                    UPDATE PBIEMBEDDEDREPORTCONFIG SET FORCEREDEPLOY = 1
                                END";

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Retrieves all of the Databases on a SQL Server.
        /// </summary>
        /// <returns>Returns the list of database names.</returns>
        public IEnumerable<string> ListDatabaseNames()
        {
            const string NameColumn = "name";

            List<string> databaseNames = new List<string>();

            string sqlCommand = string.Format(CultureInfo.InvariantCulture, @"SELECT {0} FROM dbo.sysdatabases WHERE name != 'master'", NameColumn);

            using (DataTable dataTable = this.ExecuteSQLQuery(sqlCommand))
            {
                foreach (DataRow row in dataTable.Rows)
                {
                    string name = (string)row[NameColumn];
                    databaseNames.Add(name);
                }

                return databaseNames;
            }
        }

        /// <summary>
        /// Check for the restore DB version is Ax2012 or not.
        /// </summary>
        /// <returns>Returns bool.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes", Justification = "By design.")]
        public bool CheckAX2012Database()
        {
            string sqlCommand = string.Format(CultureInfo.InvariantCulture, @"select count(*) as count from INFORMATION_SCHEMA.TABLES  where TABLE_NAME = 'TableIDTable'");

            bool doesntHaveTableIdTable = false;
            bool ax2012releaseVersion = false;

            using (DataTable dataTable = this.ExecuteSQLQuery(sqlCommand))
            {
                foreach (DataRow row in dataTable.Rows)
                {
                    if (Convert.ToInt32(row[0], CultureInfo.InvariantCulture) == 0)
                    {
                        doesntHaveTableIdTable = true;
                    }
                }
            }

            sqlCommand = string.Format(CultureInfo.InvariantCulture, @"Select top 1 description from SysSetupLog where Name = 'ReleaseUpdateDBGetFromVersion' order by description desc");

            try
            {
                using (DataTable dataTable = this.ExecuteSQLQuery(sqlCommand))
                {
                    foreach (DataRow row in dataTable.Rows)
                    {
                        if (Convert.ToInt32(row[0], CultureInfo.InvariantCulture) <= 30)
                        {
                            ax2012releaseVersion = true;
                        }
                    }
                }
            }
            catch (Exception)
            {
                ax2012releaseVersion = false;
            }

            return doesntHaveTableIdTable && ax2012releaseVersion;
        }

        /// <summary>
        /// Returns a list of SQL Processes running on the server.
        /// </summary>
        /// <returns>Returns a List of SqlProcessExecutions.</returns>
        public IEnumerable<SqlProcessExecution> ListSQLSessions()
        {
            const string SqlCommand = @"IF OBJECT_ID (N'tempdb..#WhatsRunning') IS NOT NULL 
                     DROP TABLE #WhatsRunning
            ;with blocksinfo1
            as
            (
            select spid, '' as parentspid, program_name as spidprogramname,hostname from  sys.sysprocesses (NOLOCK) a where blocked = 0
            and spid in ( select blocked  from   sys.sysprocesses a where blocked <> 0)
            union
            select spid, blocked as parentspid, program_name as spidprogramname, hostname from  sys.sysprocesses (NOLOCK) where blocked <> 0
            ),
            blocksinfo2
            as
            (select *, cast(spid as nvarchar(30)) AS hierarchy from blocksinfo1 where parentspid = 0
                   union all
                   select m.*, cast((hierarchy+'.'+cast(m.spid as nvarchar(30))) as NVARCHAR(30)) AS hierarchy  
                         from blocksinfo1 m join blocksinfo2 on m.parentspid = blocksinfo2.spid)
            SELECT r.*,
                ISNULL(BLOCKED.wait_time, 0) AS wait_time,
                CASE
                    WHEN BLOCKED.wait_resource like 'objectk%' THEN 'Object'
                    WHEN BLOCKED.wait_resource like 'page%' THEN 'Page'
                    WHEN BLOCKED.wait_resource like 'key%' THEN 'Key'
                    WHEN BLOCKED.wait_resource like 'rid%' THEN 'Row'
                    ELSE 'N/A'
                END AS wait_resource,
                BLOCKEDSQL.text AS SQLText,
                ISNULL((BLOCKED.total_elapsed_time), 0) AS DurationInMilliSeconds into #WhatsRunning
                FROM blocksinfo2 r
                   left outer join sys.dm_exec_requests blocked on blocked.session_id = r.spid
                   OUTER APPLY sys.dm_exec_sql_text(BLOCKED.sql_handle) AS BLOCKEDSQL 
            Order by hierarchy
            ;

            Insert into #WhatsRunning
            select spid, '' as parentspid, program_name as spidprogramname,  hostname, '' as hierarchy, 0 wait_time, 'N/A' as wait_resource,
                          text as SQLText, total_elapsed_time AS DurationInMilliSeconds 
            from  sys.sysprocesses p  (NOLOCK)
                              INNER JOIN sys.dm_exec_requests  AS cn ON cn.session_id = p.spid
                                 OUTER  APPLY       sys.dm_exec_sql_text(cn.sql_handle)      
            where spid > 50 and blocked = 0
            and database_id = db_id()
            AND p.[status] <> 'background'
            AND p.spid <> @@spid
            AND SPID NOT IN ( SELECT spid from #WhatsRunning)
            AND total_elapsed_time > 120000;

            update #WhatsRunning
            SET SQLText =        text
            from  sys.sysprocesses p  (nolock)
                   INNER JOIN #WhatsRunning T ON p.spid = T.spid
                              INNER JOIN sys.dm_exec_connections  AS cn ON cn.session_id = p.spid
                                 OUTER  APPLY    sys.dm_exec_sql_text(cn.most_recent_sql_handle)        
                                 LEFT   JOIN       sys.dm_exec_query_stats AS qs ON most_recent_sql_handle = qs.sql_handle
            where T.SQLText IS NULL;

            SELECT * FROM #WhatsRunning;";

            var processes = new List<SqlProcessExecution>();

            using (DataTable dataTable = this.ExecuteSQLQuery(SqlCommand))
            {
                foreach (DataRow row in dataTable.Rows)
                {
                    processes.Add(new SqlProcessExecution()
                    {
                        SessionProcessID = row[0] is DBNull ? 0 : Convert.ToInt32(row[0], CultureInfo.InvariantCulture),
                        ParentSessionProcessId = row[1] is DBNull ? 0 : Convert.ToInt32(row[1], CultureInfo.InvariantCulture),
                        ProgramName = row[2] is DBNull ? null : (string)row[2],
                        HostName = row[3] is DBNull ? null : (string)row[3],
                        Hierarchy = row[4] is DBNull ? null : (string)row[4],
                        WaitTime = row[5] is DBNull ? 0 : Convert.ToInt32(row[5], CultureInfo.InvariantCulture),
                        WaitResource = row[6] is DBNull ? null : (string)row[6],
                        SQLText = row[7] is DBNull ? null : (string)row[7],
                        DurationInMilliSeconds = row[8] is DBNull ? 0 : Convert.ToInt64(row[8], CultureInfo.InvariantCulture),
                    });
                }
            }

            return processes;
        }

        /// <summary>
        /// Initiates the Terminate SQL Session call.
        /// </summary>
        /// <param name="sessionId">The Session ID to terminate.</param>
        /// <returns>Returns the SQL Message.</returns>
        public string TerminateSQLSession(int sessionId)
        {
            Contract.Requires(sessionId > 0);

            const string SqlCommandTemplate = "KILL {0};";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, sessionId);

            return this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Execute a SQL Command against a given connection.
        /// </summary>
        /// <param name="sqlCommandTemplate">The template for sql command to execute.</param>
        /// <param name="sqlQueryParameters">The list of SQL query parameters to pass to the template.</param>
        /// <param name="queryMessage">Out variable that contains the informational message from the SQL Command.</param>
        /// <param name="sqlCommandTimeout">The time in seconds to wait for the command to execute. The default is 30 seconds.</param>
        /// <returns>Returns the SQL Information Message.</returns>
        [SuppressMessage("Microsoft.Design", "CA1026:DefaultParametersShouldNotBeUsed", Justification = "By Design.")]
        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Query does not come from user input and we are using SQL command parameters.")]
        public bool ExecuteSQLTemplateCommand(string sqlCommandTemplate, IEnumerable<SQLActionParameter> sqlQueryParameters, out string queryMessage, TimeSpan? sqlCommandTimeout = null)
        {
            string infoMessage = string.Empty;
            using (var connection = new SqlConnection(this.sqlConnection.ConnectionString))
            {
                connection.Open();

                connection.InfoMessage += delegate (object sender, SqlInfoMessageEventArgs e)
                {
                    infoMessage += e.Message;
                };

                using (var sqlCommand = connection.CreateCommand())
                {
                    if (sqlCommandTimeout.HasValue)
                    {
                        sqlCommand.CommandTimeout = (int)sqlCommandTimeout.Value.TotalSeconds;
                    }

                    this.AddSQLParameters(sqlCommand, sqlQueryParameters);

                    sqlCommand.CommandText = sqlCommandTemplate;
                    sqlCommand.CommandType = System.Data.CommandType.Text;

                    try
                    {
                        sqlCommand.ExecuteNonQuery();
                    }
                    catch (SqlException se)
                    {
                        if (se.Number == -2)
                        {
                            queryMessage = "The SQL operation has timed out, please select the parameter \"Use Fast Query\" and set to \"No\" and try again.";
                        }
                        else
                        {
                            queryMessage = se.Message;
                        }

                        return false;
                    }
                }
            }

            queryMessage = infoMessage;
            return true;
        }

        /// <summary>
        /// Returns the results of a SQL Query as a DataTable.
        /// </summary>
        /// <param name="sqlCommandTemplate">The template for sql command to execute.</param>
        /// <param name="sqlQueryParameters">The list of SQL query parameters to pass to the template.</param>
        /// <param name="queryMessage">Out variable that contains the informational message from the SQL Query.</param>
        /// <param name="sqlCommandTimeout">The time in seconds to wait for the command to execute. The default is 30 seconds.</param>
        /// <returns>Returns a DataTable representation of the query.</returns>
        [SuppressMessage("Microsoft.Design", "CA1026:DefaultParametersShouldNotBeUsed", Justification = "By Design.")]
        [SuppressMessage("Microsoft.Reliability", "CA2000:DisposeObjectsBeforeLosingScope", Justification = "We do not want to dispose object, This should be handled from the caller.")]
        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Query does not come from user input and we are using SQL command parameters.")]
        public DataTable ExecuteSQLTemplateQuery(string sqlCommandTemplate, IEnumerable<SQLActionParameter> sqlQueryParameters, out string queryMessage, TimeSpan? sqlCommandTimeout = null)
        {
            DataTable dataTable = new DataTable();
            dataTable.Locale = CultureInfo.InvariantCulture;
            string infoMessage = string.Empty;

            using (var connection = new SqlConnection(this.sqlConnection.ConnectionString))
            {
                connection.Open();

                connection.InfoMessage += delegate (object sender, SqlInfoMessageEventArgs e)
                {
                    infoMessage += e.Message;
                };

                using (var sqlCommand = connection.CreateCommand())
                {
                    if (sqlCommandTimeout.HasValue)
                    {
                        sqlCommand.CommandTimeout = (int)sqlCommandTimeout.Value.TotalSeconds;
                    }

                    this.AddSQLParameters(sqlCommand, sqlQueryParameters);

                    sqlCommand.CommandText = sqlCommandTemplate;
                    sqlCommand.CommandType = System.Data.CommandType.Text;

                    try
                    {
                        using (SqlDataReader reader = sqlCommand.ExecuteReader())
                        {
                            dataTable.Load(reader);
                        }
                    }
                    catch (SqlException se)
                    {
                        if (se.Number == -2)
                        {
                            queryMessage = "The SQL operation has timed out, please select the parameter \"Use Fast Query\" and set to \"No\" and try again.";
                        }
                        else
                        {
                            queryMessage = se.Message;
                        }

                        return null;
                    }
                }
            }

            queryMessage = infoMessage;
            return dataTable;
        }

        /// <summary>
        /// Update  sysserverconfig set throttlingsqlutilizationreservationlimit value.
        /// </summary>
        /// <param name="settingValue">Setting value.</param>
        public void UpdateSysServerConfigThrottlingSqlLimit(int settingValue)
        {
            string configName = "Throttlingsqlutilizationreservationlimit";
            this.UpdateSysServerConfig(configName, settingValue);
        }

        /// <summary>
        /// Update  SysGlobalConfiguration table name = 'DATAAREAIDLITERAL' or name = 'PARTITIONLITERAL' value .
        /// </summary>
        /// <param name="settingValue">Setting value.</param>
        public void UpdateSysGlobalConfigurationLiteral(int settingValue)
        {
            // name = 'DATAAREAIDLITERAL' or name = 'PARTITIONLITERAL'  ;
            string whereClause = "Name = 'DATAAREAIDLITERAL' or Name = 'PARTITIONLITERAL'";
            this.UpdateSysGlobalConfiguration(whereClause, settingValue);
        }

        /// <summary>
        /// Update  SysGlobalConfiguration table RC Values.
        /// </summary>
        /// <param name="settingValue">Setting value.</param>
        public void UpdateSysGlobalConfigurationRecordCacheValue(int settingValue)
        {
            // NAME LIKE 'RC_% AND NAME <>'RC_RICHCLIENTDIVIDEFACTOR' ;
            string whereClause = @"Name in ('RC_FRAMEWORK', 'RC_GROUP', 'RC_MAIN', 'RC_MISCELLANEOUS', 'RC_PARAMETER','RC_REFERENCE', 'RC_TRANSACTION',
                                            'RC_TRANSACTIONHEADER', 'RC_TRANSACTIONLINE', 'RC_WORKSHEET','RC_WORKSHEETHEADER', 'RC_WORKSHEETLINE')";
            this.UpdateSysGlobalConfiguration(whereClause, settingValue);
        }

        /// <summary>
        /// Adds an AX application service user into AX and assignts it the specified roles.
        /// </summary>
        /// <param name="user">The AX Application User.</param>
        public void AddAXApplicationUser(AXApplicationUser user)
        {
            Contract.Requires(!String.IsNullOrEmpty(user.UserName));
            Contract.Requires(Regex.IsMatch(user.UserName, UserNamePattern));

            // Create the AX user if it doesn't exist
            string sqlCommand = CommonAxSqlScripts.AddAXApplicationUser(user);

            this.ExecuteSQLCommand(sqlCommand);

            // Apply the roles to the AX user
            foreach (UserRole role in user.UserRoles)
            {
                sqlCommand = CommonAxSqlScripts.AssignRoleToUser(user, role);
                this.ExecuteSQLCommand(sqlCommand);
            }
        }

        /// <summary>
        /// Add an entry into the AX SysAadClientTable.
        /// </summary>
        /// <param name="applicationId">The AAD Application ID for the application.</param>
        /// <param name="axUserId">The AX User ID to associate this entry with.</param>
        /// <param name="aadEntryName">The name of the entry for the table.</param>
        public void AddApplicationIdToAxAadClientTable(string applicationId, string axUserId, string aadEntryName)
        {
            Contract.Requires(!String.IsNullOrEmpty(applicationId));
            Contract.Requires(!String.IsNullOrEmpty(axUserId));
            Contract.Requires(Regex.IsMatch(aadEntryName, UserNamePattern));

            // Create the entry if the app ID is not already in the table.
            string sqlCommand = CommonAxSqlScripts.AddAadApplicationUser(applicationId, axUserId, aadEntryName);
            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Update  sysserverconfig table.
        /// </summary>
        /// <param name="configName">The name of the field name to update.</param>
        /// <param name="settingValue">Setting value.</param>
        private void UpdateSysServerConfig(string configName, int settingValue)
        {
            const string SqlCommandTemplate = "UPDATE SYSSERVERCONFIG SET {0}= {1}";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, configName, settingValue);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Update  SysGlobalConfiguration table.
        /// </summary>
        /// <param name="whereClause">The where clause in the update query.</param>
        /// <param name="settingValue">Setting value.</param>
        private void UpdateSysGlobalConfiguration(string whereClause, int settingValue)
        {
            const string SqlCommandTemplate = "UPDATE SYSGLOBALCONFIGURATION SET VALUE = {0} WHERE {1}";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, settingValue, whereClause);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Sets some general database setting.
        /// </summary>
        /// <param name="databaseName">The target database name.</param>
        /// <param name="settingName">The name of the setting to set.</param>
        /// <param name="settingValue">The value of the setting to set.</param>
        private void SetDatabaseSetting(string databaseName, string settingName, string settingValue)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);
            Contract.Requires(!String.IsNullOrWhiteSpace(settingName));

            const string SqlCommandTemplate = "ALTER DATABASE [{0}] SET {1} {2};";
            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, databaseName, settingName, settingValue);

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Sets some database-scope flag.
        /// </summary>
        /// <param name="flagName">The name of the flag to set.</param>
        /// <param name="enable">Indicates if flag should be enabled or disabled.</param>
        private void SetDatabaseScopedFlag(string flagName, bool enable)
        {
            const string SqlCommandTemplate = @"ALTER DATABASE SCOPED CONFIGURATION SET {0} = {1}";

            string sqlCommand = String.Format(CultureInfo.InvariantCulture, SqlCommandTemplate, flagName, enable ? "ON" : "OFF");

            this.ExecuteSQLCommand(sqlCommand);
        }

        /// <summary>
        /// Execute a SQL Command against a given connection.
        /// </summary>
        /// <param name="sqlCommandTemplate">The template for sql command to execute.</param>
        /// <param name="sqlCommandTimeout">The time in seconds to wait for the command to execute. The default is 30 seconds.</param>
        /// <returns>Returns the SQL Information Message.</returns>
        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Query does not come from user input.")]
        private string ExecuteSQLCommand(string sqlCommandTemplate, TimeSpan? sqlCommandTimeout = null)
        {
            string infoMessage = string.Empty;
            using (var connection = new SqlConnection(this.sqlConnection.ConnectionString))
            {
                connection.Open();

                connection.InfoMessage += delegate (object sender, SqlInfoMessageEventArgs e)
                {
                    infoMessage += e.Message;
                };

                using (var sqlCommand = connection.CreateCommand())
                {
                    if (sqlCommandTimeout.HasValue)
                    {
                        sqlCommand.CommandTimeout = (int)sqlCommandTimeout.Value.TotalSeconds;
                    }

                    sqlCommand.CommandText = sqlCommandTemplate;
                    sqlCommand.CommandType = System.Data.CommandType.Text;
                    sqlCommand.ExecuteNonQuery();
                }
            }

            return infoMessage;
        }

        /// <summary>
        /// Execute a SQL Command against a given connection.
        /// </summary>
        /// <param name="sqlCommandTemplate">The template for sql command to execute.</param>
        /// <param name="sqlCommandTimeout">The time in seconds to wait for the command to execute. The default is 30 seconds.</param>
        /// <returns>Returns the SQL Information Message.</returns>
        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Query does not come from user input.")]
        private string ExecuteSQLCommand(string sqlCommandTemplate, SqlParameter[] parameters, TimeSpan? sqlCommandTimeout = null)
        {
            string infoMessage = string.Empty;
            using (var connection = new SqlConnection(this.sqlConnection.ConnectionString))
            {
                connection.Open();

                connection.InfoMessage += delegate (object sender, SqlInfoMessageEventArgs e)
                {
                    infoMessage += e.Message;
                };

                using (var sqlCommand = connection.CreateCommand())
                {
                    if (sqlCommandTimeout.HasValue)
                    {
                        sqlCommand.CommandTimeout = (int)sqlCommandTimeout.Value.TotalSeconds;
                    }

                    sqlCommand.CommandText = sqlCommandTemplate;
                    sqlCommand.CommandType = System.Data.CommandType.Text;
                    sqlCommand.Parameters.AddRange(parameters);
                    sqlCommand.ExecuteNonQuery();
                }
            }

            return infoMessage;
        }

        /// <summary>
        /// Returns the results of a SQL Query as a DataTable.
        /// </summary>
        /// <param name="sqlCommandTemplate">The template for sql command to execute.</param>
        /// <returns>Returns a DataTable representation of the query.</returns>
        [SuppressMessage("Microsoft.Reliability", "CA2000:DisposeObjectsBeforeLosingScope", Justification = "We do not want to dispose object, This should be handled from the caller.")]
        [SuppressMessage("Microsoft.Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Query does not come from user input.")]
        private DataTable ExecuteSQLQuery(string sqlCommandTemplate)
        {
            DataTable dataTable = new DataTable();
            dataTable.Locale = CultureInfo.InvariantCulture;

            using (var connection = new SqlConnection(this.sqlConnection.ConnectionString))
            {
                connection.Open();
                using (var sqlCommand = connection.CreateCommand())
                {
                    sqlCommand.CommandText = sqlCommandTemplate;
                    sqlCommand.CommandType = System.Data.CommandType.Text;

                    using (SqlDataReader reader = sqlCommand.ExecuteReader())
                    {
                        dataTable.Load(reader);
                    }
                }
            }

            return dataTable;
        }

        /// <summary>
        /// Gets the Geo-Replication Link Status for the particular database.
        /// </summary>
        /// <param name="databaseName">The name of the database to get the status on.</param>
        /// <returns>Returns a SqlRole value of the current databases role. 0 = Primary and 1 = Secondary.</returns>
        private SqlRole GetGeoReplicationRole(string databaseName)
        {
            Contract.Requires(!String.IsNullOrEmpty(databaseName));
            Contract.Requires(databaseName.Length < DatabaseNameMaxLength);

            string sqlCommand = string.Format(CultureInfo.InvariantCulture, "SELECT [role] FROM [sys].geo_replication_links WHERE partner_database = '{0}';", databaseName);

            const string RoleColumn = "role";

            using (DataTable dataTable = this.ExecuteSQLQuery(sqlCommand))
            {
                if (dataTable.Rows.Count >= 1)
                {
                    DataRow row = dataTable.Rows[0];
                    int role = Convert.ToInt32(row[RoleColumn], CultureInfo.InvariantCulture);
                    return (SqlRole)role;
                }
                else
                {
                    return SqlRole.Unknown;
                }
            }
        }

        /// <summary>
        /// Adds the SQL Parameters to the the SqlCommand object.
        /// </summary>
        /// <param name="sqlCommand">The Sql Command object to populate the parameters.</param>
        /// <param name="parameters">The list of SQL Action Parameters to add to the Sql Command.</param>
        private void AddSQLParameters(SqlCommand sqlCommand, IEnumerable<SQLActionParameter> parameters)
        {
            foreach (SQLActionParameter parameter in parameters)
            {
                // Switch is here to do a type check on the values passed.
                bool validValue = true;
                SqlParameter sqlParameter;

                switch (parameter.DotNetType)
                {
                    case Library.Constants.StringParameterType:
                        sqlParameter = new SqlParameter(parameter.SQLParameterName, SqlDbType.NVarChar);
                        break;
                    case Library.Constants.ByteParameterType:
                        byte byteValue;
                        validValue = byte.TryParse(parameter.Value, out byteValue);
                        sqlParameter = new SqlParameter(parameter.SQLParameterName, SqlDbType.TinyInt);
                        break;
                    case Library.Constants.ShortParameterType:
                        short int16Value;
                        validValue = Int16.TryParse(parameter.Value, out int16Value);
                        sqlParameter = new SqlParameter(parameter.SQLParameterName, SqlDbType.SmallInt);
                        break;
                    case Library.Constants.IntParameterType:
                        int int32Value;
                        validValue = Int32.TryParse(parameter.Value, out int32Value);
                        sqlParameter = new SqlParameter(parameter.SQLParameterName, SqlDbType.Int);
                        break;
                    case Library.Constants.LongParameterType:
                        long int64Value;
                        validValue = Int64.TryParse(parameter.Value, out int64Value);
                        sqlParameter = new SqlParameter(parameter.SQLParameterName, SqlDbType.BigInt);
                        break;
                    case Library.Constants.BooleanParameterType:
                        bool booleanValue;
                        validValue = Boolean.TryParse(parameter.Value, out booleanValue);
                        sqlParameter = new SqlParameter(parameter.SQLParameterName, SqlDbType.Bit);
                        break;
                    case Library.Constants.DateTimeParameterType:
                        DateTime dateTimeValue;
                        validValue = DateTime.TryParse(parameter.Value, out dateTimeValue);
                        sqlParameter = new SqlParameter(parameter.SQLParameterName, SqlDbType.DateTime);
                        break;
                    default:
                        throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "The Argument [{0}] was an unknown data type of [{1}]", parameter.SQLParameterName, parameter.DotNetType));
                }

                if (!validValue)
                {
                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "The Argument [{0}] was not a data type of [{1}]", parameter.SQLParameterName, parameter.DotNetType));
                }

                if (parameter.Value == null)
                {
                    sqlParameter.Value = DBNull.Value;
                }
                else
                {
                    sqlParameter.Value = parameter.Value;
                }

                sqlCommand.Parameters.Add(sqlParameter);
            }
        }

        /// <summary>
        /// Class used to encapsulate SQL login information.
        /// </summary>
        public class SqlLogin
        {
            /// <summary>
            /// Gets or sets the name of the login.
            /// </summary>
            public string Name { get; set; }

            /// <summary>
            /// Gets or sets the sid of the login, a unique hex value represented in string form.
            /// </summary>
            public string Sid { get; set; }
        }

        /// <summary>
        /// Class use to encapsulate the Active SQL Process.
        /// </summary>
        public class SqlProcessExecution
        {
            /// <summary>
            /// Gets or sets the unique session ID of the process.
            /// </summary>
            public int SessionProcessID { get; set; }

            /// <summary>
            /// Gets or sets the session ID of the Parent.
            /// </summary>
            public int ParentSessionProcessId { get; set; }

            /// <summary>
            /// Gets or sets the name of the calling program.
            /// </summary>
            public string ProgramName { get; set; }

            /// <summary>
            /// Gets or sets the name of the calling host.
            /// </summary>
            public string HostName { get; set; }

            /// <summary>
            /// Gets or sets the SQL Hierarchy.
            /// </summary>
            public string Hierarchy { get; set; }

            /// <summary>
            /// Gets or sets the current wait time in milliseconds of the Process.
            /// </summary>
            public int WaitTime { get; set; }

            /// <summary>
            /// Gets or sets the process' wait resource.
            /// </summary>
            public string WaitResource { get; set; }

            /// <summary>
            /// Gets or sets the SQL Text that was run.
            /// </summary>
            public string SQLText { get; set; }

            /// <summary>
            /// Gets or sets the length of the process in milliseconds.
            /// </summary>
            public long DurationInMilliSeconds { get; set; }
        }
    }
}
