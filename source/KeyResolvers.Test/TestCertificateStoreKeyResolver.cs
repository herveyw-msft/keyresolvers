
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace KeyResolvers.Test
{
    public class TestCertificateStoreKeyResolver : IClassFixture<TestFixture>
    {
        private TestFixture _fixture;

        public TestCertificateStoreKeyResolver( TestFixture fixture )
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task TestResolver()
        {
            var resolver = new CertificateStoreKeyResolver( StoreName.My, StoreLocation.CurrentUser );
            var key      = await resolver.ResolveKeyAsync( _fixture.Thumbprint ).ConfigureAwait( false );

            Assert.NotNull( key );
            Assert.Equal( key.Kid, _fixture.Thumbprint );
        }
    }
}
