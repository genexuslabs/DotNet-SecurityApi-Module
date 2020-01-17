
using GeneXusJWT.GenexusJWTClaims;
using SecurityAPICommons.Commons;
using System.Security;

namespace GeneXusJWT.GenexusComons
{
    [SecuritySafeCritical]
    public abstract class JWTObject : SecurityAPIObject
    {
        public abstract string DoCreate(string algorithm, PrivateClaims privateClaims, JWTOptions options);
        public abstract bool DoVerify(string token, PrivateClaims privateClaims, JWTOptions options);
        public abstract string GetPayload(string token);
        public abstract string GetHeader(string token);
        public abstract string GetTokenID(string token);

    }
}
