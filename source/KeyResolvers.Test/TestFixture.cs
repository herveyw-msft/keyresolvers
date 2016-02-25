
using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KeyResolvers.Test
{
    public class TestFixture : IDisposable
    {
        X509Store _store;
        string    _thumbprint;

        public TestFixture()
        {
            _store = new X509Store( StoreName.My, StoreLocation.CurrentUser );

            _store.Open( OpenFlags.ReadWrite );

            // The PFX in the resources file is Base64 encoded, the .NET API
            // cannot deal with this so decode it here before loading it.
            var certificateString = UTF8Encoding.UTF8.GetString( Properties.Resources.Certificate );
            var certificateBytes  = Convert.FromBase64String( certificateString );

            var certificate = new X509Certificate2( certificateBytes, string.Empty );

            // Remember the thumprint
            _thumbprint = certificate.Thumbprint;

            // Add the certificate to the store
            _store.Add( certificate );

            _store.Close();
        }

        public string Thumbprint
        {
            get { return _thumbprint; }
        }

        #region IDisposable

        public void Dispose()
        {
            Dispose( true );
            GC.SuppressFinalize( this );
        }

        protected virtual void Dispose( bool disposing )
        {
            if ( disposing )
            {
                _store = new X509Store( StoreName.My, StoreLocation.CurrentUser );
                _store.Open( OpenFlags.ReadWrite );

                X509Certificate2Collection certificates = _store.Certificates.Find( X509FindType.FindByThumbprint, _thumbprint, false );

                if ( certificates.Count > 0 )
                {
                    _store.Certificates.Remove( certificates[0] );
                }

                _store.Close();
            }
        }

        #endregion IDisposable
    }
}
