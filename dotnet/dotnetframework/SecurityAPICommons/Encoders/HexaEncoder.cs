using SecurityAPICommons.Commons;
using SecurityAPICommons.Config;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Security;


namespace SecurityAPICommons.Encoders
{
    /// <summary>
    /// Implements hexadecimal encoding and decoding functions
    /// </summary>
    [SecuritySafeCritical]
    public class HexaEncoder : SecurityAPIObject
    {


        /// <summary>
        /// Hexa class contructor
        /// </summary>

        [SecuritySafeCritical]
        public HexaEncoder() : base()
        {

        }

        /// <summary>
        /// string Hexadecimal encoded representation of UTF-8 input plain text
        /// </summary>
        /// <param name="plainText">string UTF-8 plain text</param>
        /// <returns>string Hexa hexadecimal representation of plainText</returns>
        [SecuritySafeCritical]
        public string toHexa(string plainText)
        {
            byte[] digest = new EncodingUtil().getBytes(plainText);
            string result = BitConverter.ToString(digest).Replace("-", string.Empty);
            if (result == null || result.Length == 0)
            {
                this.error.setError("HE001", "Error encoding hexa");
                return "";
            }
            this.error.cleanError();
            return result;

        }
        /// <summary>
        /// string UTF-8 representation of the STring hexadecimal encoded text
        /// </summary>
        /// <param name="stringHexa">string hexadecimal representation of a text</param>
        /// <returns>string UTF-8 plain text from stringHexa</returns>
        [SecuritySafeCritical]
        public string fromHexa(string stringHexa)
        {
            byte[] stringBytes = Hex.Decode(stringHexa);
            string result = Strings.FromByteArray(stringBytes);
            if (result == null || result.Length == 0)
            {
                this.error.setError("HE002", "Error decoding hexa");
                return "";
            }
            this.error.cleanError();
            return result;
        }
    }
}
