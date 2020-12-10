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
        public bool setClaim(string key, object value)
        {
            return base.setClaim(key, value, new Error());
        }

        [SecuritySafeCritical]
        public bool setClaim(string key, PrivateClaims value)
        {
            return base.setClaim(key, value, new Error());
        }

        [SecuritySafeCritical]
        public Dictionary<string, object> getNestedMap()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            // System.out.println("size: "+getAllClaims().size());
            foreach (Claim c in getAllClaims())
            {
                if (c.getValue() != null)
                {

                    result.Add(c.getKey(), c.getValue());
                }
                else
                {
                    result.Add(c.getKey(), ((PrivateClaims)c.getNestedClaims()).getNestedMap());
                }
            }

            return result;
        }
    }
}
