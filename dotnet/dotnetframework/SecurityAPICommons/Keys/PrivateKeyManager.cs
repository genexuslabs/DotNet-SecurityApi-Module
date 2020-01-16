using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Nist;
using SecurityAPICommons.Commons;
using SecurityAPICommons.Utils;

namespace SecurityAPICommons.Keys
{
    [SecuritySafeCritical]
    public class PrivateKeyManager : PrivateKey
    {

        private PrivateKeyInfo privateKeyInfo;
        private bool hasPrivateKey;
        public bool HasPrivateKey
        {
            get { return hasPrivateKey; }
        }
        private string privateKeyAlgorithm;

        [SecuritySafeCritical]
        public PrivateKeyManager() : base()
        {
            this.hasPrivateKey = false;

        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/

        [SecuritySafeCritical]
        public bool Load(String privateKeyPath)
        {
            return LoadPKCS12(privateKeyPath, "", "");
        }


        [SecuritySafeCritical]
        public bool LoadPKCS12(String privateKeyPath, String alias, String password)
        {
            try
            {
                loadKeyFromFile(privateKeyPath, alias, password);
            }
            catch (Exception)
            {

                return false;
            }
            if (this.HasError())
            {
                return false;
            }
            return true;
        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

        [SecuritySafeCritical]
        public AsymmetricAlgorithm getPrivateKeyForXML()
        {

            string algorithm = getPrivateKeyAlgorithm();
            if (SecurityUtils.compareStrings("RSA", algorithm))
            {


                byte[] serializedPrivateBytes = this.privateKeyInfo.ToAsn1Object().GetDerEncoded();
                string serializedPrivate = Convert.ToBase64String(serializedPrivateBytes);
                RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(serializedPrivate));
                return DotNetUtilities.ToRSA(privateKey);


            }
            else
            {
                this.error.setError("PK002", "XML signature with ECDSA keys is not implemented on Net Framework");
                return null;
                //https://stackoverflow.com/questions/27420789/sign-xml-with-ecdsa-and-sha256-in-net?rq=1
                // https://www.powershellgallery.com/packages/Posh-ACME/2.6.0/Content/Private%5CConvertFrom-BCKey.ps1

            }

        }

        /// <summary>
        /// Return AsymmetricKeyParameter with private key for the indicated algorithm
        /// </summary>
        /// <returns>AsymmetricKeyParameter type for signing, algorithm dependant</returns>
        [SecuritySafeCritical]
        public AsymmetricKeyParameter getPrivateKeyParameterForSigning()
        {


            if (SecurityUtils.compareStrings(this.getPrivateKeyAlgorithm(), "RSA"))
            {
                return getRSAKeyParameter();
            }
            if (SecurityUtils.compareStrings(this.getPrivateKeyAlgorithm(), "ECDSA"))
            {
                AsymmetricKeyParameter parmsECDSA;
                try
                {
                    parmsECDSA = PrivateKeyFactory.CreateKey(this.privateKeyInfo);
                }
                catch (IOException e)
                {
                    this.error.setError("AE007", "Not ECDSA key");
                    return null;
                    throw e;
                }
                return parmsECDSA;
            }
            this.error.setError("AE008", "Unrecognized algorithm");
            return null;

        }
        /// <summary>
        /// Return AsymmetricKeyParameter with private key for the indicated algorithm
        /// </summary>
        /// <returns>AsymmetricKeyParameter type for encryption, algorithm dependant</returns>
        [SecuritySafeCritical]
        public AsymmetricKeyParameter getPrivateKeyParameterForEncryption()
        {


            if (SecurityUtils.compareStrings(this.getPrivateKeyAlgorithm(), "RSA"))
            {
                return getRSAKeyParameter();
            }

            this.error.setError("AE009", "Unrecognized encryption algorithm");
            return null;

        }

        /// <summary>
        /// Returns AsymmetricKeyParameter for RSA key types
        /// </summary>
        /// <param name="isPrivate"> boolean true if its a private key, false if its a public key</param>
        /// <returns>AsymmetricKeyParameter for RSA with loaded key</returns>
        private AsymmetricKeyParameter getRSAKeyParameter()
        {
            RsaKeyParameters parms;
            try
            {
                parms = (RsaKeyParameters)PrivateKeyFactory.CreateKey(this.privateKeyInfo);
            }
            catch (IOException e)
            {
                this.error.setError("AE013", "Not RSA key");
                return null;
                throw e;
            }
            return parms;
        }



        /// <summary>
        /// Returns private key for signing https://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
        /// </summary>
        /// <returns>string certificate's algorithm for signing, 1.2.840.113549.1.1.1 if RSA from key pem file</returns>
        [SecuritySafeCritical]
        public string getPrivateKeyAlgorithm()
        {

            if (SecurityUtils.compareStrings(this.privateKeyAlgorithm, "1.2.840.113549.1.1.1") || SecurityUtils.compareStrings(this.privateKeyAlgorithm, "RSA"))
            {
                return "RSA";
            }
            if (SecurityUtils.compareStrings(this.privateKeyAlgorithm, "1.2.840.10045.2.1") || SecurityUtils.compareStrings(this.privateKeyAlgorithm, "EC"))
            {
                return "ECDSA";
            }
            return this.privateKeyAlgorithm.ToUpper();
        }

        /// <summary>
        /// Stores structure of public or private key from any type of certificate
        /// </summary>
        /// <param name="path">string of the certificate file</param>
        /// <param name="alias">Srting certificate's alias, required if PKCS12</param>
        /// <param name="password">string certificate's password, required if PKCS12</param>
        /// <param name="isPrivate"></param>
        /// <returns>boolean true if private key, boolean false if public key</returns>
        internal bool loadKeyFromFile(string path, string alias, string password)
        {
            return loadPrivateKeyFromFile(path, alias, password);
        }
        private bool loadPrivateKeyFromFile(string path, string alias, string password)
        {

            bool flag = false;
            if (SecurityUtils.extensionIs(path, ".pem"))
            {
                return loadPrivateKeyFromPEMFile(path);
            }
            if (SecurityUtils.extensionIs(path, ".pfx") || SecurityUtils.extensionIs(path, ".p12"))
            {
                return loadPrivateKeyFromPKCS12File(path, password);
            }
            if (SecurityUtils.extensionIs(path, ".jks"))
            {
                this.error.setError("PK003", "Java Key Stores not allowed on .Net applications");
                //throw new Exception("Java Key Stores not allowed on .Net applications");
            }

            return flag;
        }

        /// <summary>
        /// Stores PrivateKeyInfo Data Type from certificate's private key, algorithm and digest
        /// </summary>
        /// <param name="path">string .ps12, pfx or .jks (PKCS12 fromat) certificate path</param>
        /// <param name="password">string certificate's password, required if PKCS12</param>
        /// <returns></returns>
        private bool loadPrivateKeyFromPKCS12File(string path, string password)
        {
            bool flag = false;
            if (password == null)
            {
                this.error.setError("PK004", "Alias and Password are required for PKCS12 keys");
                return false;
            }
            Pkcs12Store pkcs12 = null;

            try
            {
                pkcs12 = new Pkcs12StoreBuilder().Build();
                pkcs12.Load(new FileStream(path, FileMode.Open, FileAccess.Read), password.ToCharArray());

            }

            catch
            {
                this.error.setError("PK005", path + "not found or wrong password.");
                //throw new FileLoadException(path + "not found or wrong password.");
            }

            if (pkcs12 != null)
            {
                string pName = null;
                foreach (string n in pkcs12.Aliases)
                {
                    if (pkcs12.IsKeyEntry(n) && pkcs12.GetKey(n).Key.IsPrivate)
                    {
                        pName = n;

                        this.privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pkcs12.GetKey(n).Key);
                        this.privateKeyAlgorithm = this.privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Id;
                        this.hasPrivateKey = true;
                        return true;
                    }
                }

            }
            this.error.setError("PK006", path + " not found");
            return flag;

        }

        /// <summary>
        /// stores PrivateKeyInfo Data Type from certificate's private key
        /// </summary>
        /// <param name="path">string .pem certificate path</param>
        /// <returns>boolean true if loaded correctly</returns>
        private bool loadPrivateKeyFromPEMFile(string path)
        {
            bool flag = false;
            StreamReader streamReader = new StreamReader(path);
            PemReader pemReader = new PemReader(streamReader);
            Object obj = pemReader.ReadObject();
            if (obj.GetType() == typeof(RsaPrivateCrtKeyParameters))
            {
                AsymmetricKeyParameter asymKeyParm = (AsymmetricKeyParameter)obj;
                this.privateKeyInfo = createPrivateKeyInfo(asymKeyParm);
                this.privateKeyAlgorithm = this.privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Id;
                this.hasPrivateKey = true;
                closeReaders(streamReader, pemReader);
                return true;
            }
            if (obj.GetType() == typeof(Pkcs8EncryptedPrivateKeyInfo))
            {
                this.error.setError("PK007", "Encrypted key, remove the key password");
                flag = false;
            }
            if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
            {
                AsymmetricCipherKeyPair asymKeyPair = (AsymmetricCipherKeyPair)obj;
                this.privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymKeyPair.Private);
                this.privateKeyAlgorithm = this.privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Id;
                this.hasPrivateKey = true;
                return true;
            }
            if (obj.GetType() == typeof(X509Certificate))
            {
                this.error.setError("PK008", "The file contains a public key");
                flag = false;

            }
            closeReaders(streamReader, pemReader);
            return flag;

        }

        /// <summary>
        /// Excecute close methods of PemReader and StreamReader data types
        /// </summary>
        /// <param name="streamReader">StreamReader type</param>
        /// <param name="pemReader">PemReader type</param>
        private void closeReaders(StreamReader streamReader, PemReader pemReader)
        {
            try
            {
                streamReader.Close();
                pemReader.Reader.Close();
            }
            catch
            {
                this.error.setError("PK012", "Error closing StreamReader/ PemReader for certificates");
            }
        }

        /// <summary>
        /// Build private PrivateKeyInfo
        /// https://csharp.hotexamples.com/examples/Org.BouncyCastle.Asn1.Pkcs/RsaPrivateKeyStructure/-/php-rsaprivatekeystructure-class-examples.html
        /// </summary>
        /// <param name="key">AsymmetricKeyParameter key</param>
        /// <returns>PrivateKeyInfo from AsymmetricKeyParameter </returns>
        private PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter key)
        {

            if (key is DsaPrivateKeyParameters)
            {

                DsaPrivateKeyParameters _key = (DsaPrivateKeyParameters)key;
                this.hasPrivateKey = true;
                this.privateKeyAlgorithm = "ECDSA";
                return new PrivateKeyInfo(
                    new AlgorithmIdentifier(
                    X9ObjectIdentifiers.IdDsa,
                    new DsaParameter(
                    _key.Parameters.P,
                    _key.Parameters.Q,
                    _key.Parameters.G).ToAsn1Object()),
                    new DerInteger(_key.X));
            }


            if (key is RsaKeyParameters)
            {
                AlgorithmIdentifier algID = new AlgorithmIdentifier(
                    PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);

                RsaPrivateKeyStructure keyStruct;
                if (key is RsaPrivateCrtKeyParameters)
                {
                    RsaPrivateCrtKeyParameters _key = (RsaPrivateCrtKeyParameters)key;
                    this.hasPrivateKey = true;
                    this.privateKeyAlgorithm = "RSA";
                    keyStruct = new RsaPrivateKeyStructure(
                        _key.Modulus,
                        _key.PublicExponent,
                        _key.Exponent,
                        _key.P,
                        _key.Q,
                        _key.DP,
                        _key.DQ,
                        _key.QInv);
                }
                else
                {
                    RsaKeyParameters _key = (RsaKeyParameters)key;
                    this.hasPrivateKey = true;
                    this.privateKeyAlgorithm = "RSA";
                    keyStruct = new RsaPrivateKeyStructure(
                        _key.Modulus,
                        BigInteger.Zero,
                        _key.Exponent,
                        BigInteger.Zero,
                        BigInteger.Zero,
                        BigInteger.Zero,
                        BigInteger.Zero,
                        BigInteger.Zero);
                }

                return new PrivateKeyInfo(algID, keyStruct.ToAsn1Object());
            }
            this.error.setError("PK013", "Class provided is not convertible: " + key.GetType().FullName);
            this.hasPrivateKey = false;
            throw new ArgumentNullException("Class provided is not convertible: " + key.GetType().FullName);

        }
    }
}
