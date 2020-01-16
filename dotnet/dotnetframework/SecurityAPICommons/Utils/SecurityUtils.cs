
using System.Security;

namespace SecurityAPICommons.Utils
{
    [SecuritySafeCritical]
    public class SecurityUtils
    {

        /// <summary>
        /// Compares two strings ignoring casing
        /// </summary>
        /// <param name="one">string to compare</param>
        /// <param name="two">string to compare</param>
        /// <returns>true if both strings are equal ignoring casing</returns>
        [SecuritySafeCritical]
        public static bool compareStrings(string one, string two)
        {
            return string.Compare(one, two, true) == 0;
        }

        /// <summary>
        /// Verifies if the file has some extension type
        /// </summary>
        /// <param name="path">path to the file</param>
        /// <param name="ext">extension of the file</param>
        /// <returns>true if the file has the extension</returns>
        [SecuritySafeCritical]
        public static bool extensionIs(string path, string ext)
        {
            return string.Compare(getFileExtension(path), ext, true) == 0;
        }
        /// <summary>
        /// Gets a file extension from the file's path
        /// </summary>
        /// <param name="path">path to the file</param>
        /// <returns>file extension</returns>
        [SecuritySafeCritical]
        public static string getFileExtension(string path)
        {

            int lastIndexOf = path.LastIndexOf(".");
            if (lastIndexOf == -1)
            {
                return ""; // empty extension
            }
            return path.Substring(lastIndexOf);
        }
    }
}
