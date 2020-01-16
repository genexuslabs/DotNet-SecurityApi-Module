
using SecurityAPICommons.Commons;
using System.Security;

namespace GeneXusJWT.GenexusComons
{
    [SecuritySafeCritical]
    public abstract class GUIDObject : SecurityAPIObject

    {
        public abstract string Generate();
    }
}
