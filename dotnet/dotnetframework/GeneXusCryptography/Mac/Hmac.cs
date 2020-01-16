using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using SecurityAPICommons.Commons;
using GeneXusCryptography.Commons;
using SecurityAPICommons.Config;
using Org.BouncyCastle.Utilities.Encoders;
using System.Security.Cryptography;
using GeneXusCryptography.Hash;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Macs;
using GeneXusCryptography.HashUtils;
using SecurityAPICommons.Utils;

namespace GeneXusCryptography.Mac
{
    [SecuritySafeCritical]
    public class Hmac : SecurityAPIObject, IHmacObject
    {

        public Hmac() : base()
        {

        }

        /********EXTERNAL OBJECT PUBLIC METHODS  - BEGIN ********/
        [SecuritySafeCritical]
        public string calculate(string plainText, string password, string algorithm)
        {
            byte[] pass = Hex.Decode(password);
            EncodingUtil eu = new EncodingUtil();
            byte[] inputBytes = eu.getBytes(plainText);
            if (this.HasError())
            {
                return "";
            }
            Hashing hash = new Hashing();
            HashUtils.HashAlgorithm alg = HashAlgorithmUtils.getHashAlgorithm(algorithm, this.error);
            if (this.HasError())
            {
                return "";
            }
            IDigest digest = hash.createHash(alg);
            HMac engine = new HMac(digest);
            engine.Init(new KeyParameter(pass));
            byte[] resBytes = new byte[engine.GetMacSize()];
            engine.BlockUpdate(inputBytes, 0, inputBytes.Length);
            engine.DoFinal(resBytes, 0);

            string result = toHexastring(resBytes);
            if (!this.error.existsError())
            {
                return result;
            }
            return "";

        }

        [SecuritySafeCritical]
        public bool verify(string plainText, string password, string mac, string algorithm)
        {
            string res = calculate(plainText, password, algorithm);
            return SecurityUtils.compareStrings(res, mac);
        }
        /********EXTERNAL OBJECT PUBLIC METHODS  - END ********/

        /// <summary>
        /// Gets the hexadecimal encoded representation of the digest input
        /// </summary>
        /// <param name="digest">byte array</param>
        /// <returns>string Hexa respresentation of the byte array digest</returns>
        private string toHexastring(byte[] digest)
        {
            string result = BitConverter.ToString(digest).Replace("-", string.Empty);
            if (result == null || result.Length == 0)
            {
                this.error.setError("HS001", "Error encoding hexa");
                return "";
            }
            return result;
        }
    }
}
