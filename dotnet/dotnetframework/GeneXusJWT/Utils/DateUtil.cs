using System;
using System.Security;
using System.Globalization;
using GeneXusJWT.GenexusComons;


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

        [SecuritySafeCritical]
        public string CurrentPlusMinutes(long minutes)
        {
            DateTime date = DateTime.ParseExact(DateTime.UtcNow.AddMinutes(minutes).ToString("yyyy/MM/dd HH:mm:ss"), "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
            return date.ToString("yyyy/MM/dd HH:mm:ss");
        }

        [SecuritySafeCritical]
        public string CurrentPlusHours(long hours)
        {
            DateTime date = DateTime.ParseExact(DateTime.UtcNow.AddHours(hours).ToString("yyyy/MM/dd HH:mm:ss"), "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
            return date.ToString("yyyy/MM/dd HH:mm:ss");
        }

        [SecuritySafeCritical]
        public string CurrentPlusDays(long days)
        {
            DateTime date = DateTime.ParseExact(DateTime.UtcNow.AddDays(days).ToString("yyyy/MM/dd HH:mm:ss"), "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
            return date.ToString("yyyy/MM/dd HH:mm:ss");
        }

        [SecuritySafeCritical]
        public string CurrentPlusMonths(int months)
        {
            DateTime date = DateTime.ParseExact(DateTime.UtcNow.AddMonths(months).ToString("yyyy/MM/dd HH:mm:ss"), "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture);
            return date.ToString("yyyy/MM/dd HH:mm:ss");
        }
        [SecuritySafeCritical]
        public string LastDayOfCurrentMonth(string time)
        {
            DateTime date;
            try
            {
                date = DateTime.ParseExact(time, "HH:mm:ss", CultureInfo.InvariantCulture);
            }
            catch (Exception)
            {
                this.error.setError("DU001", "Wrong format in input parameter");
                return "";
            }
            int hour = date.Hour;
            int minutes = date.Minute;
            int seconds = date.Second;
            int day = DateTime.DaysInMonth(DateTime.UtcNow.Year, DateTime.UtcNow.Month);
            int year = DateTime.UtcNow.Year;
            int month = DateTime.UtcNow.Month;
            String result;
            try
            {
                result = String.Format("{0}/{1:D2}/{2:D2} {3:D2}:{4:D2}:{5:D2}", year, month, day, hour, minutes, seconds);
            }
            catch (Exception)
            {
                this.error.setError("DU002", "Could not generate correct date");
                return "";
            }
            return result;
        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - END ********/
    }
}
