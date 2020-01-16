using GeneXusJWT.GenexusComons;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using SecurityAPICommons.Commons;

namespace GeneXusJWT.GenexusJWTUtils
{
    [SecuritySafeCritical]
    public class GUID : GUIDObject
    {


        [SecuritySafeCritical]
        public GUID() : base()
        {

        }

        [SecuritySafeCritical]
        public override string Generate()
        {
            return System.Guid.NewGuid().ToString();
        }
    }
}
