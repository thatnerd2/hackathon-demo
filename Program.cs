
using System;
using System.Data;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.Web;
using System.Data.SqlTypes;
using System.Xml;
using System.Security;
using Microsoft.AspNetCore.Mvc;

namespace HackathonExamples
{
    public class ThreadSafety
    {
        int mBalance = 0;
        private readonly object balanceLock = new object();

        public void deposit(int amount)
        {
            if (amount > 0)
            {
                lock (balanceLock)
                {
                    mBalance += amount;
                }
            }
        }

        public int withdraw(int amount)
        {
            if (amount >= 0 && mBalance - amount >= 0)
            {
                mBalance -= amount;
                return mBalance;
            }
            else
            {
                return 0;
            }
        }
    }

    public class FunctionalMethods
    {
        /// <summary>
        /// Gets an access key for the Batch account.
        /// </summary>
        /// <param name="getPrimaryKey">Indicates whether to retrieve the primary or secondary key.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        internal static SecureString GetKeyAsync(bool getPrimaryKey = true, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            SecureString value = null;

            var key = "klj;4k2j3k2";
            value = new SecureString();
            foreach (var c in key)
            {
                value.AppendChar(c);
            }

            return value;
        }


    }



}