using SecurityAPICommons.Commons;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;

namespace GeneXusJWT.GenexusComons
{
    [SecuritySafeCritical]
    public abstract class DateUtilObject : SecurityAPIObject
    {
        public abstract string GetCurrentDate();
        public abstract string CurrentPlusSeconds(long seconds);
        public abstract string CurrentMinusSeconds(long seconds);
    }
}
