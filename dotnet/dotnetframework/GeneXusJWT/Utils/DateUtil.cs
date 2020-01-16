using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Globalization;
using GeneXusJWT.GenexusComons;
using SecurityAPICommons.Commons;

namespace GeneXusJWT.GenexusJWTUtils
{
    [SecuritySafeCritical]
    public class DateUtil : DateUtilObject
    {


        [SecuritySafeCritical]
        public DateUtil() : base()
        {

        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
        [SecuritySafeCritical]
        public override string GetCurrentDate()
        {
            DateTime date = DateTime.ParseExact(DateTime.UtcNow.ToString("yyyy/MM/dd HH:mm:ss"), "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
            return date.ToString("yyyy/MM/dd HH:mm:ss");
        }

        [SecuritySafeCritical]
        public override string CurrentMinusSeconds(long seconds)
        {
            DateTime date = DateTime.ParseExact(DateTime.UtcNow.AddSeconds(-seconds).ToString("yyyy/MM/dd HH:mm:ss"), "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
            return date.ToString("yyyy/MM/dd HH:mm:ss");
        }

        [SecuritySafeCritical]
        public override string CurrentPlusSeconds(long seconds)
        {
            DateTime date = DateTime.ParseExact(DateTime.UtcNow.AddSeconds(seconds).ToString("yyyy/MM/dd HH:mm:ss"), "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
            return date.ToString("yyyy/MM/dd HH:mm:ss");
        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - END ********/
    }
}
