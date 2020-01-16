using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;

namespace GeneXusJWT.GenexusJWTClaims
{
    [SecuritySafeCritical]
    public class Claim
    {

        private string key;
        private string value;

        [SecuritySafeCritical]
        public Claim(string valueKey, string valueOfValue)
        {
            key = valueKey;
            value = valueOfValue;
        }

        [SecuritySafeCritical]
        public string getValue()
        {
            return value;
        }

        [SecuritySafeCritical]
        public string getKey()
        {
            return key;
        }
    }
}
