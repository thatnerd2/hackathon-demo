namespace Microsoft.DynamicsOnline.Infrastructure.IdGen
{
    using System;
    using System.Collections.Generic;
    using System.Web;
    using Microsoft.DynamicsOnline.Infrastructure.Extensions;

    internal sealed class IdChunkInfo
    {
        public int MidId { get; set; }
        public int HighId { get; set; }

        private int current;
        private int limit;

        /// <summary>
        /// Initializes a new instance of the <see cref="IdChunkInfo"/> class.
        /// </summary>
        /// <param name="lowId">The low id.</param>
        /// <param name="chunkSize">Size of the chunk.</param>
        /// <param name="highId">The high id.</param>
        internal IdChunkInfo(int chunkSize, int lowId, int midId, int highId)
        {
            this.HighId = highId;
            this.MidId = midId;
            this.current = lowId;
            this.limit = lowId + chunkSize;
        }

        /// <summary>
        /// increments the current lowId value and returns it
        /// </summary>
        internal int LowId
        {
            get
            {
                return (System.Threading.Interlocked.Increment(ref this.current) - 1);
            }
        }

        /// <summary>
        /// chunk upper limit
        /// </summary>
        internal int Limit
        {
            get
            {
                return this.limit;
            }
        }
    }

    /// <summary>
    /// help class that holds an Int64 Ids structure information
    /// </summary>
    internal sealed class IdInfo
    {
        private UInt64 lowId;
        private UInt64 midId;
        private UInt64 highId;
        private UInt64 metadata = 0;

        /// <summary>
        /// Prevents a new instance of the <see cref="IdInfo"/> class from being created.
        /// </summary>
        private IdInfo()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IdInfo"/> class.
        /// </summary>
        /// <param name="lowId">The low id.</param>
        /// <param name="highId">The high id.</param>
        /// <param name="objectType">Type of the object.</param>
        /// <param name="serviceType">Type of the service.</param>
        internal IdInfo(int lowId, int midId, int highId)
        {
            //
            // bits 0-31
            //
            this.lowId = (UInt32)lowId;
            //
            // bits 32-47
            //
            this.midId = (UInt64)((UInt16)midId) << 32;
            //
            // bits 48-55
            //
            this.highId = (UInt64)((byte)highId) << 48;
        }

        /// <summary>
        /// returns the Id based on the following rule
        /// bits 0-31 -> lowId
        /// bits 32-47 -> highId
        /// bits 48-55 -> objectType
        /// bits 56-63 -> serviceType
        /// </summary>
        internal UInt64 Id
        {
            get
            {
                return (this.lowId | this.midId | this.highId | this.metadata);
            }
        }
    }

    /// <summary>
    /// Class used to generate new Int64 Ids
    /// </summary>
    public sealed partial class IdGenerator
    {
        #region private_members

        /// <summary>
        /// holds info about a chunk of Ids
        /// </summary>
        /// <summary>
        /// Private class used to cache and renew chunks of Ids
        /// </summary>
        private sealed class IdChunk
        {
            private object fetchingLock = new object();

            private IdChunkInfo chunkInfo;

            /// <summary>
            /// ctor
            /// </summary>
            public IdChunk()
            {
            }

            //
            // calls DB layer to fetch a new chunk of Ids
            //
            private IdChunkInfo FetchNew(StorageUri storageUri, Guid idRangeKey)
            {
                IdBlockFetcher idBlockFetcher = new IdBlockFetcher();
                return idBlockFetcher.FetchNew(storageUri, idRangeKey);
            }


            /// <summary>
            /// returns the following available Id from this chunk. If needed, the chunk refreshes itself
            /// fetching a new block of Ids from DB
            /// </summary>
            internal IdInfo GetNewId(StorageUri storageUri, Guid idRangeKey)
            {
                if (this.chunkInfo == null)
                {
                    lock (this.fetchingLock)
                    {
                        //
                        // see if another thread hasn't already succeeded to fetch a new chunk
                        //
                        if (this.chunkInfo == null)
                        {
                            this.chunkInfo = this.FetchNew(storageUri, idRangeKey);
                        }
                    }
                }
            //
            // see if we need to fetch a new block
            //
            CheckIfFetchNeeded:
                //
                // make first a local copy to avoid multi-threading issues
                //
                IdChunkInfo localChunkInfo = this.chunkInfo;
                //
                // get a new lowId
                // Note: the LowId property increments the current value and returns it
                //
                int lowId = localChunkInfo.LowId;
                //
                // see if it is valid
                //
                if (lowId >= localChunkInfo.Limit)
                {
                    lock (this.fetchingLock)
                    {
                        //
                        // see if another thread hasn't already succeeded to fetch a new chunk
                        //
                        if (object.ReferenceEquals(localChunkInfo, this.chunkInfo))
                        {
                            this.chunkInfo = this.FetchNew(storageUri, idRangeKey);
                        }
                    }
                    goto CheckIfFetchNeeded;
                }
                return new IdInfo(lowId, localChunkInfo.MidId, localChunkInfo.HighId);
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IdGenerator"/> class.
        /// </summary>
        private IdGenerator()
        {
        }

        //
        // the lock object that enforces the singleton instance
        //
        private static object instanceLocker = new object();
        private static volatile IdGenerator instance = null;

        //
        // the idchunk handed out
        //
        private Dictionary<string, Dictionary<Guid, IdChunk>> storage = new Dictionary<string, Dictionary<Guid, IdChunk>>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Get a new id from the idgen sql table under the storage URI's (logical store, storage namespace)'s connection string
        /// The idrange is keyed by the idRangeKey
        /// </summary>
        /// <param name="storageUri"></param>
        /// <param name="idRangeKey"></param>
        /// <returns></returns>
        internal long GetNewIdInternal(StorageUri storageUri, Guid idRangeKey)
        {
            IdChunk idChunk = null;
            string physicalStore = storageUri.ActualStorageName;
            if (this.storage.ContainsKey(physicalStore) &&
                this.storage[physicalStore].ContainsKey(idRangeKey))
            {
                idChunk = this.storage[physicalStore][idRangeKey];
            }
            if (idChunk == null)
            {
                idChunk = new IdChunk();
                lock (IdGenerator.instanceLocker)
                {
                    // check for contentions
                    if (this.storage.ContainsKey(physicalStore) &&
                        this.storage[physicalStore].ContainsKey(idRangeKey))
                    {
                        idChunk = this.storage[physicalStore][idRangeKey];
                    }
                    else
                    {
                        if (!this.storage.ContainsKey(physicalStore))
                        {
                            this.storage.Add(physicalStore, new Dictionary<Guid, IdChunk>());
                        }
                        this.storage[physicalStore][idRangeKey] = idChunk;
                    }
                }
            }
            // it is now dawning on me that coupling fetch capability to IdChunk class was a bad idea.
            // it makes us need to pass these parameters to idChunk which it shouldn't need, except
            // it needs to pass them thru to the fetch routine.
            return (long)(idChunk.GetNewId(storageUri, idRangeKey).Id);
        }


        #endregion
    }
}
