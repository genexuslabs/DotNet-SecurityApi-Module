using System.Runtime.CompilerServices;


/*[assembly: InternalsVisibleTo("SecurityAPITestNetCore")]
[assembly: InternalsVisibleTo("SecurityAPITest")]*/
namespace SecurityAPICommons.Config
{

    internal static class Global
    {
        private static string global_encoding = "UTF_8";
        public static string GLOBAL_ENCODING
        {
            get
            {
                if (global_encoding == null)
                {
                    return "UTF_8";
                }
                return global_encoding;
            }
            set
            {
                global_encoding = value;
            }
        }



    }
}
