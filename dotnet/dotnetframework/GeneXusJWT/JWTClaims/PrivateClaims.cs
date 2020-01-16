
using SecurityAPICommons.Commons;
using System.Collections.Generic;
using System.Security;

namespace GeneXusJWT.GenexusJWTClaims
{
    [SecuritySafeCritical]
    public class PrivateClaims : Claims
    {
        private List<Claim> _claims;

        [SecuritySafeCritical]
        public bool setClaim(string key, string value)
        {
            return base.setClaim(key, value, new Error());
        }
    }
}
