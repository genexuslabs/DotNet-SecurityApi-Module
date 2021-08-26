﻿
using GeneXusCryptography.AsymmetricUtils;
using GeneXusCryptography.Hash;
using GeneXusCryptography.HashUtils;
using SecurityAPICommons.Commons;
using SecurityAPICommons.Config;
using SecurityAPICommons.Keys;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities.Encoders;
using GeneXusCryptography.Commons;
using System;
using System.Security;
using SecurityAPICommons.Utils;

namespace GeneXusCryptography.Asymmetric
{
    /// <summary>
    /// Implements Asymmetric Signer engines and methods to sign and verify signatures
    /// </summary>
    [SecuritySafeCritical]
    public class AsymmetricSigner : SecurityAPIObject, IAsymmetricSignerObject
    {


        /// <summary>
        /// AsymmetricSigner class constructor
        /// </summary>
        public AsymmetricSigner() : base()
        {

        }

        /********EXTERNAL OBJECT PUBLIC METHODS  - BEGIN ********/

        [SecuritySafeCritical]
        public string DoSign(PrivateKeyManager key, string hashAlgorithm, string plainText)
        {
            EncodingUtil eu = new EncodingUtil();
            byte[] inputText = eu.getBytes(plainText);
            if (eu.HasError())
            {
                this.error = eu.GetError();
                return "";
            }
            return DoSignPKCS12(key, hashAlgorithm, inputText);
        }

        [SecuritySafeCritical]
        public string DoSignFile(PrivateKeyManager key, string hashAlgorithm, string path)
        {
            byte[] input = SecurityUtils.getFileBytes(path, this.error);
            if (this.HasError())
            {
                return "";
            }
            return DoSignPKCS12(key, hashAlgorithm, input);
        }



        [SecuritySafeCritical]
        public bool DoVerify(CertificateX509 cert, string plainText, string signature)
        {
            EncodingUtil eu = new EncodingUtil();
            byte[] inputText = eu.getBytes(plainText);
            if (eu.HasError())
            {
                this.error = eu.GetError();
                return false;
            }
            return DoVerifyPKCS12(cert, inputText, signature);
        }

        [SecuritySafeCritical]
        public bool DoVerifyFile(CertificateX509 cert, String path, String signature)
        {
            byte[] input = SecurityUtils.getFileBytes(path, this.error);
            if (this.HasError())
            {
                return false;
            }
            return DoVerifyPKCS12(cert, input, signature);
        }

        /********EXTERNAL OBJECT PUBLIC METHODS  - END ********/

        /// <summary>
        /// Signs UTF-8 plain text
        /// </summary>
        /// <param name="path">string path of the key/certificate file</param>
        /// <param name="hashAlgorithm">string HashAlgorithm enum, algorithm name</param>
        /// <param name="alias">string alias of the certificate/keystore in pkcs12 format</param>
        /// <param name="password">string password of the certificate/keystore in pkcs12 format</param>
        /// <param name="plainText">string UTF-8 text to sign</param>
        /// <returns>string Base64 signature of plainText text</returns>
        private string DoSignPKCS12(PrivateKey key, string hashAlgorithm, byte[] input)
        {
            this.error.cleanError();
            HashAlgorithm hash = HashAlgorithmUtils.getHashAlgorithm(hashAlgorithm, this.error);
            if (this.error.existsError())
            {
                return "";
            }
            PrivateKeyManager keyMan = (PrivateKeyManager)key;
            string algorithm = keyMan.getPrivateKeyAlgorithm();
            if (keyMan.GetError().existsError())
            {
                this.error = keyMan.GetError();
                return "";
            }

            if (SecurityUtils.compareStrings(algorithm, "RSA"))
            {
                return signRSA(hash, input, keyMan);
            }
            if (SecurityUtils.compareStrings(algorithm, "ECDSA"))
            {
                return signECDSA(hash, input, keyMan);
            }
            this.error.setError("AE047", "Unrecognized signing algorithm " + algorithm);
            return "";
        }

        /// <summary>
        /// Implements signature verification with RSA or ECDSA keys
        /// </summary>
        /// <param name="path">string path of the key/certificate file</param>
        /// <param name ="alias">string alias of the certificate/keystore in pkcs12 format</param>
        /// <param name="password">string password of the certificate/keystore in pkcs12 format</param>
        /// <param name="plainText">string UTF-8 text to sign</param>
        /// <param name="signature">string Base64 signature of plainText</param>
        /// <returns>boolean true if signature is valid for the specified parameters, false if it is invalid</returns>
        private bool DoVerifyPKCS12(Certificate certificate, byte[] input, string signature)
        {
            this.error.cleanError();
            CertificateX509 cert = (CertificateX509)certificate;
            if (!cert.Inicialized || cert.HasError())
            {
                this.error = cert.GetError();
                return false;
            }
            AsymmetricSigningAlgorithm asymmetricSigningAlgorithm = AsymmetricSigningAlgorithmUtils.getAsymmetricSigningAlgorithm(cert.getPublicKeyAlgorithm(), this.error);
            if (this.error.existsError())
            {
                return false;
            }
            switch (asymmetricSigningAlgorithm)
            {
                case AsymmetricSigningAlgorithm.RSA:
                    return verifyRSA(input, signature, cert);
                case AsymmetricSigningAlgorithm.ECDSA:
                    return verifyECDSA(input, signature, cert);
                default:
                    this.error.setError("AE048", "Cannot verify signature");
                    return false;
            }

        }


        private bool verifyRSA(byte[] input, string signature, CertificateX509 cert)
        {

            HashAlgorithm hashAlgorithm = (HashAlgorithm)Enum.Parse(typeof(HashAlgorithm), cert.getPublicKeyHash());
            if (HashAlgorithm.NONE != hashAlgorithm)
            {
                Hashing digest = new Hashing();
                IDigest hash = digest.createHash(hashAlgorithm);
                if (digest.GetError().existsError())
                {
                    this.error = digest.GetError();
                    return false;
                }
                RsaDigestSigner signerRSA = new RsaDigestSigner(hash);
                AsymmetricKeyParameter asymmetricKeyParameter = cert.getPublicKeyParameterForSigning();
                signerRSA.Init(false, asymmetricKeyParameter);
                signerRSA.BlockUpdate(input, 0, input.Length);
                byte[] signatureBytes = Base64.Decode(signature);
                if (signatureBytes == null || signatureBytes.Length == 0)
                {
                    this.error.setError("AE049", "Error on signature verification");
                    return false;
                }
                this.error.cleanError();
                return signerRSA.VerifySignature(signatureBytes);
            }
            this.error.setError("AE050", "Hashalgorithm cannot be NONE");
            return false;
        }
        /// <summary>
        /// Implements signature verification with ECDSA keys, if no hash is defined uses default SHA1
        /// </summary>
        /// <param name="plainText">string UTF-8 signed text</param>
        /// <param name="signature">string Base64 signature of plainText</param>
        /// <param name="km">KeyManager Data Type loaded with keys and key information</param>
        /// <returns>boolean true if signature is valid for the specified parameters, false if it is invalid</returns>
        private bool verifyECDSA(byte[] input, string signature, CertificateX509 cert)
        {
            HashAlgorithm hashAlgorithm;
            if (SecurityUtils.compareStrings(cert.getPublicKeyHash(), "ECDSA"))
            {
                hashAlgorithm = HashAlgorithm.SHA1;
            }
            else
            {
                hashAlgorithm = (HashAlgorithm)Enum.Parse(typeof(HashAlgorithm), cert.getPublicKeyHash());
            }
            Hashing hash = new Hashing();
            IDigest digest = hash.createHash(hashAlgorithm);
            if (hash.GetError().existsError())
            {
                this.error = hash.GetError();
                return false;
            }
            ECDsaSigner dsaSigner = new ECDsaSigner();
            DsaDigestSigner digestSigner = new DsaDigestSigner(dsaSigner, digest);
            AsymmetricKeyParameter asymmetricKeyParameter = cert.getPublicKeyParameterForSigning();
            if (this.error.existsError())
            {
                return false;
            }
            digestSigner.Init(false, asymmetricKeyParameter);
            digestSigner.BlockUpdate(input, 0, input.Length);
            byte[] signatureBytes = Base64.Decode(signature);
            if (signatureBytes == null || signatureBytes.Length == 0)
            {
                this.error.setError("AE051", "Error on signature verification");
                return false;
            }
            this.error.cleanError();
            return digestSigner.VerifySignature(signatureBytes);

        }
        /// <summary>
        /// Implements ECDSA signature. Uses specified hash value or SHA1 for default
        /// </summary>
        /// <param name="hashAlgorithm">HashAlgorithm enum, algorithm name</param>
        /// <param name="plainText">string UTF-8 to sign</param>
        /// <param name="km">KeyManager Data Type loaded with keys and key information</param>
        /// <returns>string Base64 ECDSA signature of plainText</returns>
        private string signECDSA(HashAlgorithm hashAlgorithm, byte[] input, PrivateKeyManager km)
        {
            Hashing hash = new Hashing();
            IDigest digest = hash.createHash(hashAlgorithm);
            if (hash.GetError().existsError())
            {
                this.error = hash.GetError();
                return "";
            }
            ECDsaSigner dsaSigner = new ECDsaSigner();
            DsaDigestSigner digestSigner = new DsaDigestSigner(dsaSigner, digest);
            AsymmetricKeyParameter asymmetricKeyParameter = km.getPrivateKeyParameterForSigning();
            if (this.error.existsError())
            {
                return "";
            }
            digestSigner.Init(true, asymmetricKeyParameter);
            digestSigner.BlockUpdate(input, 0, input.Length);
            byte[] output = digestSigner.GenerateSignature();
            if (output == null || output.Length == 0)
            {
                this.error.setError("AE052", "Error on signing");
            }
            this.error.cleanError();
            return Base64.ToBase64String(output);

        }
        /// <summary>
        /// Implements RSSA signature. Hash NONE is not a valid value
        /// </summary>
        /// <param name="hashAlgorithm">HashAlgorithm enum, algorithm name</param>
        /// <param name="plainText">string UTF-8 to sign</param>
        /// <param name="km">KeyManager Data Type loaded with keys and key information</param>
        /// <returns>string Base64 RSA signature of plainText</returns>
        private string signRSA(HashAlgorithm hashAlgorithm, byte[] input, PrivateKeyManager km)
        {
            if (HashAlgorithm.NONE != hashAlgorithm)
            {
                Hashing digest = new Hashing();
                IDigest hash = digest.createHash(hashAlgorithm);
                if (digest.GetError().existsError())
                {
                    this.error = digest.GetError();
                    return "";
                }
                RsaDigestSigner signerRSA = new RsaDigestSigner(hash);
                AsymmetricKeyParameter asymmetricKeyParameter = km.getPrivateKeyParameterForSigning();
                if (this.error.existsError())
                {

                    return "";
                }
                signerRSA.Init(true, asymmetricKeyParameter);
                signerRSA.BlockUpdate(input, 0, input.Length);
                byte[] outputBytes;
                try
                {
                    outputBytes = signerRSA.GenerateSignature();
                }
                catch (DataLengthException dle)
                {
                    this.error.setError("AE053", "RSA signing error");
                    throw new DataLengthException("RSA signing error", dle);
                }
                catch (CryptoException ce)
                {
                    this.error.setError("AE053", "RSA signing error");
                    throw new CryptoException("RSA signing error", ce);
                }
                this.error.cleanError();
                return Base64.ToBase64String(outputBytes);
            }
            this.error.setError("AE054", "HashAlgorithm cannot be NONE");
            return "";

        }
    }
}
