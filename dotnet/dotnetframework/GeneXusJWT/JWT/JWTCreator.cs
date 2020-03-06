
using GeneXusJWT.GenexusComons;
using GeneXusJWT.GenexusJWTClaims;
using GeneXusJWT.GenexusJWTUtils;
using SecurityAPICommons.Commons;
using SecurityAPICommons.Config;
using SecurityAPICommons.Keys;
using SecurityAPICommons.Utils;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace GeneXusJWT.GenexusJWT
{
    [SecuritySafeCritical]
    public class JWTCreator : SecurityAPIObject
    {


        [SecuritySafeCritical]
        public JWTCreator() : base()
        {


            EncodingUtil eu = new EncodingUtil();
            eu.setEncoding("UTF8");
            /***Config to Debug - Delete on Release version!!!***/
            //Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

        /******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
        [SecuritySafeCritical]
        public string DoCreate(string algorithm, PrivateClaims privateClaims, JWTOptions options)
        {
            if (options.HasError())
            {
                this.error = options.GetError();
                return "";
            }
            JWTAlgorithm alg = JWTAlgorithmUtils.getJWTAlgorithm(algorithm, this.error);
            if (this.HasError())
            {
                return "";
            }
            if (this.HasError())
            {
                return "";
            }
            /***Hack to support 1024 RSA key lengths - BEGIN***/
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForSigningMap["RS256"] = 1024;
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForSigningMap["RS512"] = 1024;
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForSigningMap["RS384"] = 1024;     
            /***Hack to support 1024 RSA key lengths - END***/

            JwtPayload payload = doBuildPayload(privateClaims, options);

            SecurityKey genericKey = null;
            if (JWTAlgorithmUtils.isPrivate(alg))
            {

                PrivateKeyManager key = options.GetPrivateKey();
                if (key.HasError())
                {
                    this.error = key.GetError();
                    return "";
                }
                RsaSecurityKey privateKey = new RsaSecurityKey((RSA)key.getPrivateKeyForXML());
                genericKey = privateKey;
            }
            else
            {
                SymmetricSecurityKey symKey = new SymmetricSecurityKey(options.getSecret());
                genericKey = symKey;
            }

            SigningCredentials signingCredentials = JWTAlgorithmUtils.getSigningCredentials(alg, genericKey, this.error);
            if (this.HasError())
            {

                return "";
            }

            string signedJwt = "";
            try
            {
                JwtHeader header = new JwtHeader(signingCredentials);
                
                JwtSecurityToken secToken = new JwtSecurityToken(header, payload);
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                signedJwt = handler.WriteToken(secToken);
            }
            catch (Exception e)
            {
                
                this.error.setError("JW003", e.Message+ e.StackTrace);

                return "";
            }

            return signedJwt;
        }

        [SecuritySafeCritical]
        public bool DoVerify(string token, PrivateClaims privateClaims,  JWTOptions options)
        {
            if (options.HasError())
            {
                this.error = options.GetError();
                return false;
            }


            /***Hack to support 1024 RSA key lengths - BEGIN***/
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap["RS256"] = 1024;
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap["RS512"] = 1024;
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap["RS384"] = 1024;
            /***Hack to support 1024 RSA key lengths - END***/


            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = new JwtSecurityToken(token);
            bool regclaims = validateRegisteredClaims(jwtToken, options);
            bool reviqued = !isRevoqued(jwtToken, options);
            bool privClaims = verifyPrivateClaims(jwtToken, privateClaims);

            if (validateRegisteredClaims(jwtToken, options) && !isRevoqued(jwtToken, options) && verifyPrivateClaims(jwtToken, privateClaims))
            {//if validates all registered claims and it is not on revocation list
                TokenValidationParameters parms = new TokenValidationParameters();
                parms.ValidateLifetime = false;
                parms.ValidateAudience = false;
                parms.ValidateIssuer = false;
                parms.ValidateActor = false;
                JWTAlgorithm alg = JWTAlgorithmUtils.getJWTAlgorithm_forVerification(jwtToken.Header.Alg, this.error);
                if (this.HasError())
                {
                    return false;
                }
                SecurityKey genericKey = null;
                if (JWTAlgorithmUtils.isPrivate(alg))
                {


                    CertificateX509 cert = options.GetCertificate();
                    if (cert.HasError())
                    {
                        this.error = cert.GetError();
                        return false;
                    }
                    RsaSecurityKey publicKey = new RsaSecurityKey((RSA)cert.getPublicKeyXML());
                    genericKey = publicKey;
                }
                else
                {
                    SymmetricSecurityKey symKey = new SymmetricSecurityKey(options.getSecret());
                    genericKey = symKey;
                }

                SigningCredentials signingCredentials = JWTAlgorithmUtils.getSigningCredentials(alg, genericKey, this.error);
                parms.IssuerSigningKey = genericKey;
                SecurityToken validatedToken;
                try
                {
                    handler.ValidateToken(token, parms, out validatedToken);
                }
                catch (Exception e)
                {
                    this.error.setError("JW004", e.Message);

                    return false;
                }
                return true;

            }
            return false;

        }

        [SecuritySafeCritical]
        public string getPayload(string token)
        {

            return getTokenPart(token, "payload");

        }

        [SecuritySafeCritical]
        public string getHeader(string token)
        {
            return getTokenPart(token, "header");
        }

        [SecuritySafeCritical]
        public string getTokenID(string token)
        {
            return getTokenPart(token, "id");
        }


        /******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

        private JwtPayload doBuildPayload(PrivateClaims privateClaims, JWTOptions options)
        {
            JwtPayload payload = new JwtPayload();
            // ****START BUILD PAYLOAD****//
            // Adding private claims
            List<Claim> privateC = privateClaims.getAllClaims();
            foreach (Claim privateClaim in privateC)
            {
                System.Security.Claims.Claim netPrivateClaim = new System.Security.Claims.Claim(privateClaim.getKey(), privateClaim.getValue());
                payload.AddClaim(netPrivateClaim);
            }
            // Adding public claims
            if (options.hasPublicClaims())
            {
                PublicClaims publicClaims = options.getAllPublicClaims();
                List<Claim> publicC = publicClaims.getAllClaims();
                foreach (Claim publicClaim in publicC)
                {
                    System.Security.Claims.Claim netPublicClaim = new System.Security.Claims.Claim(publicClaim.getKey(), publicClaim.getValue());
                    payload.AddClaim(netPublicClaim);
                }

            }
            // Adding registered claims
            if (options.hasRegisteredClaims())
            {
                RegisteredClaims registeredClaims = options.getAllRegisteredClaims();
                List<Claim> registeredC = registeredClaims.getAllClaims();
                foreach (Claim registeredClaim in registeredC)
                {
                    System.Security.Claims.Claim netRegisteredClaim = new System.Security.Claims.Claim(registeredClaim.getKey(), registeredClaim.getValue());
                    payload.AddClaim(netRegisteredClaim);
                }
            }
            // ****END BUILD PAYLOAD****//
            return payload;
        }

        private bool validateRegisteredClaims(JwtSecurityToken jwtToken, JWTOptions options)
        {


            // Adding registered claims
            if (options.hasRegisteredClaims())
            {
                RegisteredClaims registeredClaims = options.getAllRegisteredClaims();
                List<Claim> registeredC = registeredClaims.getAllClaims();
                foreach (Claim registeredClaim in registeredC)
                {
                    string registeredClaimKey = registeredClaim.getKey();
                    string registeredClaimValue = registeredClaim.getValue();
                    if (RegisteredClaimUtils.exists(registeredClaimKey))
                    {
                        if (!RegisteredClaimUtils.isTimeValidatingClaim(registeredClaimKey))
                        {
                            if (!RegisteredClaimUtils.validateClaim(registeredClaimKey, registeredClaimValue, 0, jwtToken, this.error))
                            {
                                return false;
                            }
                        }
                        else
                        {
                            long customValidationTime = registeredClaims.getClaimCustomValidationTime(registeredClaimKey);
                            if (!RegisteredClaimUtils.validateClaim(registeredClaimKey, registeredClaimValue, customValidationTime, jwtToken, this.error))
                            {
                                return false;
                            }
                        }
                        if (this.HasError())
                        {
                            return false;
                        }


                    }
                    else
                    {
                        error.setError("JW002", registeredClaimKey + " wrong registered claim key");
                        return false;
                    }
                }
            }
            return true;
        }
        private bool isRevoqued(JwtSecurityToken jwtToken, JWTOptions options)
        {
            RevocationList rList = options.getRevocationList();
            return rList.isInRevocationList(jwtToken.Payload.Jti);
        }

        private String getTokenPart(string token, String part)
        {
            JwtSecurityToken jwtToken = new JwtSecurityToken(token);

            switch (part)
            {
                case "payload":
                    return jwtToken.Payload.SerializeToJson();
                case "header":
                    return jwtToken.Header.SerializeToJson();
                case "id":
                    return jwtToken.Payload.Jti;
                default:
                    error.setError("JW007", "Unknown token segment");
                    return "";
            }

        }

        private bool verifyPrivateClaims(JwtSecurityToken jwtToken, PrivateClaims privateClaims)
        {
            if (privateClaims == null || privateClaims.isEmpty())
            {
                return true;
            }

            JwtPayload map = jwtToken.Payload;

            List<Claim> claims = privateClaims.getAllClaims();
            for (int i = 0; i < claims.Count; i++)
            {
                Claim c = claims[i];
                if (!map.ContainsKey(c.getKey()))
                {
                    return false;
                }

                string claim =(System.String)map[c.getKey()];
                if (!SecurityUtils.compareStrings(claim.Trim(), c.getValue().Trim()))
                {
                    return false;
                }
            }
            return true;
        }
    }
}
