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
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Core;
using Microsoft.Azure.KeyVault.Cryptography;
using Microsoft.Azure.KeyVault.Cryptography.Algorithms;

namespace KeyResolvers
{
    /// <summary>
    /// An RSA key.
    /// </summary>
    public class CertificateKey : IKey, IDisposable
    {

        private X509Certificate2 _certificate;

        /// <summary>
        /// Key Identifier
        /// </summary>
        public string Kid { get; private set; }

        /// <summary>
        /// Constructor, creates a 2048 bit key with a GUID identifier.
        /// </summary>
        public CertificateKey( X509Certificate2 certificate ) : this( certificate.Thumbprint, certificate )
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public CertificateKey( string kid, X509Certificate2 certificate )
        {
            if ( string.IsNullOrWhiteSpace( kid ) )
                throw new ArgumentNullException( "kid" );

            if ( certificate == null )
                throw new ArgumentNullException( "certificate" );

            Kid = kid;

            // TODO: Check that this is a RSA certificate
            _certificate = certificate;
        }

        // Intentionally excluded.
        //~CertificateKey()
        //{
        //    Dispose( false );
        //}

        public void Dispose()
        {
            Dispose( true );
            GC.SuppressFinalize( this );
        }

        protected virtual void Dispose( bool disposing )
        {
            // Clean up managed resources if Dispose was called
            if ( disposing )
            {
            }

            // Clean up native resources always
        }

        /// <summary>
        /// Indicates whether the RSA key has only public key material.
        /// </summary>
        public bool PublicOnly
        {
            get
            {
                if ( _certificate == null )
                    throw new ObjectDisposedException( string.Format( CultureInfo.InvariantCulture, "RsaKey {0} is disposed", Kid ) );

                return !_certificate.HasPrivateKey; }
        }

        #region IKey implementation

        public string DefaultEncryptionAlgorithm
        {
            get { return RsaOaep.AlgorithmName; }
        }

        public string DefaultKeyWrapAlgorithm
        {
            get { return RsaOaep.AlgorithmName; }
        }

        public string DefaultSignatureAlgorithm
        {
            get { return Rs256.AlgorithmName; }
        }
        
// Warning 1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread.
#pragma warning disable 1998

        public async Task<byte[]> DecryptAsync( byte[] ciphertext, byte[] iv, byte[] authenticationData = null, byte[] authenticationTag = null, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "Certificate {0} is disposed", Kid ) );

            if ( !_certificate.HasPrivateKey )
                throw new NotSupportedException( "Certificate does not have a private key" );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultEncryptionAlgorithm;

            if ( ciphertext == null || ciphertext.Length == 0 )
                throw new ArgumentNullException( "ciphertext" );

            if ( iv != null )
                throw new ArgumentException( "Initialization vector must be null", "iv" );

            if ( authenticationData != null )
                throw new ArgumentException( "Authentication data must be null", "authenticationData" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            using ( var encryptor = algo.CreateDecryptor( _certificate.PrivateKey ) )
            {
                return encryptor.TransformFinalBlock( ciphertext, 0, ciphertext.Length );
            }
        }

        public async Task<Tuple<byte[], byte[], string>> EncryptAsync( byte[] plaintext, byte[] iv = null, byte[] authenticationData = null, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "Certificate {0} is disposed", Kid ) );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultEncryptionAlgorithm;

            if ( plaintext == null || plaintext.Length == 0 )
                throw new ArgumentNullException( "plaintext" );

            if ( iv != null )
                throw new ArgumentException( "Initialization vector must be null", "iv" );

            if ( authenticationData != null )
                throw new ArgumentException( "Authentication data must be null", "authenticationData" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            using ( var encryptor = algo.CreateEncryptor( _certificate.PublicKey.Key ) )
            {
                return new Tuple<byte[], byte[], string>( encryptor.TransformFinalBlock( plaintext, 0, plaintext.Length ), null, algorithm );
            }
        }

        public async Task<Tuple<byte[], string>> WrapKeyAsync( byte[] key, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultKeyWrapAlgorithm;

            if ( key == null || key.Length == 0 )
                throw new ArgumentNullException( "key" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            using ( var encryptor = algo.CreateEncryptor( _certificate.PublicKey.Key ) )
            {
                return new Tuple<byte[], string>( encryptor.TransformFinalBlock( key, 0, key.Length ), algorithm );
            }
        }

        public async Task<byte[]> UnwrapKeyAsync( byte[] encryptedKey, string algorithm = RsaOaep.AlgorithmName, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( !_certificate.HasPrivateKey )
                throw new NotSupportedException( "Certificate does not have a private key" );

            if ( string.IsNullOrWhiteSpace( algorithm ) )
                algorithm = DefaultKeyWrapAlgorithm;

            if ( encryptedKey == null || encryptedKey.Length == 0 )
                throw new ArgumentNullException( "wrappedKey" );

            AsymmetricEncryptionAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricEncryptionAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            using ( var encryptor = algo.CreateDecryptor( _certificate.PrivateKey ) )
            {
                return encryptor.TransformFinalBlock( encryptedKey, 0, encryptedKey.Length );
            }
        }

        public async Task<Tuple<byte[], string>> SignAsync( byte[] digest, string algorithm, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( !_certificate.HasPrivateKey )
                throw new NotSupportedException( "Certificate does not have a private key" );

            if ( algorithm == null )
                algorithm = DefaultSignatureAlgorithm;

            if ( digest == null )
                throw new ArgumentNullException( "digest" );

            AsymmetricSignatureAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricSignatureAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            return new Tuple<byte[], string>( algo.SignHash( _certificate.PrivateKey, digest ), algorithm );
        }

        public async Task<bool> VerifyAsync( byte[] digest, byte[] signature, string algorithm, CancellationToken token = default(CancellationToken) )
        {
            if ( _certificate == null )
                throw new ObjectDisposedException( string.Format( "RsaKey {0} is disposed", Kid ) );

            if ( digest == null )
                throw new ArgumentNullException( "digest" );

            if ( signature == null )
                throw new ArgumentNullException( "signature" );

            if ( algorithm == null )
                algorithm = DefaultSignatureAlgorithm;

            AsymmetricSignatureAlgorithm algo = AlgorithmResolver.Default[algorithm] as AsymmetricSignatureAlgorithm;

            if ( algo == null )
                throw new NotSupportedException( "algorithm is not supported" );

            return algo.VerifyHash( _certificate.PublicKey.Key, digest, signature );
        }

#pragma warning restore 1998

        #endregion
    }
}
