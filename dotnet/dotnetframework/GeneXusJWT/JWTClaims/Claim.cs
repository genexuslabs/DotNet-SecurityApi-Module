using System.Security;

namespace GeneXusJWT.GenexusJWTClaims
{
    [SecuritySafeCritical]
    public class Claim
    {

        private string key;
        private object value;

        [SecuritySafeCritical]
        public Claim(string valueKey, object valueOfValue)
        {
            key = valueKey;
            value = valueOfValue;
        }

        [SecuritySafeCritical]
        public string getValue()
        {
            if (value.GetType() == typeof(string))
            {
                return (string)value;
            }
            else { return null; }

        }

        [SecuritySafeCritical]
        public string getKey()
        {
            return key;
        }

        [SecuritySafeCritical]
        public PrivateClaims getNestedClaims()
        {
            if (value.GetType() == typeof(PrivateClaims))
            {
                return (PrivateClaims)value;
            }
            else
            {
                return null;
            }
        }
    }
}
