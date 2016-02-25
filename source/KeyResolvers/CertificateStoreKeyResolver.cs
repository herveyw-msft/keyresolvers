//
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;

namespace KeyResolvers
{
    public sealed class CertificateStoreKeyResolver : IKeyResolver
    {
        private X509Store _store;

        /// <summary>
        /// Create a new resolver that is backed by the specified X509Store. Key Identifiers
        /// are expected to be thumbprints of X509 certificates in the store.
        /// </summary>
        public CertificateStoreKeyResolver( StoreName storeName, StoreLocation storeLocation )
        {
            _store = new X509Store( storeName, storeLocation );

            // The store is held open throughout the lifetime of the resolver
            _store.Open( OpenFlags.ReadOnly );
        }

        #region IKeyResolver

        // Warning 1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread.
#pragma warning disable 1998

        /// <summary>
        /// Attempts to resolve a key identifier into an IKey implementation using
        /// an X509Store. The key identifier should be the thumprint of a certificate
        /// in the store.
        /// </summary>
        /// <param name="kid">The key identifier, a certificate thumprint</param>
        /// <param name="token">Cancellation token, not used</param>
        /// <returns>Null, or an IKey implementation using the key of the certificate</returns>
        public async Task<IKey> ResolveKeyAsync( string kid, CancellationToken token = default( CancellationToken ) )
        {
            if ( string.IsNullOrWhiteSpace( kid ) )
                throw new ArgumentNullException( "kid" );

            var collection  = _store.Certificates.Find( X509FindType.FindByThumbprint, kid, false );
            var certificate = collection.Cast<X509Certificate2>().FirstOrDefault();

            if ( certificate != null )
            {
                return new CertificateKey( kid, certificate );
            }

            return null;
        }

#pragma warning restore 1998

        #endregion
    }
}
