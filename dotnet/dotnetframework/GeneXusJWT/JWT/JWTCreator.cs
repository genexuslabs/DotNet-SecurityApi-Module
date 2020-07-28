
using GeneXusJWT.GenexusComons;
using GeneXusJWT.GenexusJWTClaims;
using GeneXusJWT.GenexusJWTUtils;
using SecurityAPICommons.Commons;
using SecurityAPICommons.Config;
using SecurityAPICommons.Keys;
using SecurityAPICommons.Utils;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using GeneXusJWT.JWTClaims;

namespace GeneXusJWT.GenexusJWT
{
    [SecuritySafeCritical]
    public class JWTCreator : SecurityAPIObject, IJWTObject
    {
        private int counter;


        [SecuritySafeCritical]
        public JWTCreator() : base()
        {


            EncodingUtil eu = new EncodingUtil();
            eu.setEncoding("UTF8");
            this.counter = 0;
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
                if (!options.GetHeaderParameters().IsEmpty())
                {
                    AddHeaderParameters(header, options);
                }

                JwtSecurityToken secToken = new JwtSecurityToken(header, payload);
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                signedJwt = handler.WriteToken(secToken);
            }
            catch (Exception e)
            {

                this.error.setError("JW003", e.Message + e.StackTrace);

                return "";
            }

            return signedJwt;
        }

        [SecuritySafeCritical]
        public bool DoVerify(string token, string expectedAlgorithm, PrivateClaims privateClaims, JWTOptions options)
        {
            if (options.HasError())
            {
                this.error = options.GetError();
                return false;
            }
            JWTAlgorithm expectedJWTAlgorithm = JWTAlgorithmUtils.getJWTAlgorithm(expectedAlgorithm, this.error);
            if (this.HasError())
            {
                return false;
            }

            /***Hack to support 1024 RSA key lengths - BEGIN***/
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap["RS256"] = 1024;
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap["RS512"] = 1024;
            AsymmetricSignatureProvider.DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap["RS384"] = 1024;
            /***Hack to support 1024 RSA key lengths - END***/


            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = new JwtSecurityToken(token);

            if (validateRegisteredClaims(jwtToken, options) && !isRevoqued(jwtToken, options) && verifyPrivateClaims(jwtToken, privateClaims, options) && VerifyHeader(jwtToken, options))
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
                if (JWTAlgorithmUtils.getJWTAlgorithm(jwtToken.Header.Alg, this.error) != expectedJWTAlgorithm || this.HasError())
                {
                    this.error.setError("JW008", "Expected algorithm does not match token algorithm");
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
        public string GetPayload(string token)
        {

            return getTokenPart(token, "payload");

        }

        [SecuritySafeCritical]
        public string GetHeader(string token)
        {
            return getTokenPart(token, "header");
        }

        [SecuritySafeCritical]
        public string GetTokenID(string token)
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

                if (privateClaim.getNestedClaims() != null)
                {

                    payload.Add(privateClaim.getKey(), privateClaim.getNestedClaims().getNestedMap());
                }
                else
                {
                    
                    System.Security.Claims.Claim netPrivateClaim = new System.Security.Claims.Claim(privateClaim.getKey(), privateClaim.getValue());

                    payload.AddClaim(netPrivateClaim);
                }

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
                    System.Security.Claims.Claim netRegisteredClaim;
                    if (RegisteredClaimUtils.isTimeValidatingClaim(registeredClaim.getKey()))
                        {

                        netRegisteredClaim = new System.Security.Claims.Claim(registeredClaim.getKey(), registeredClaim.getValue(), System.Security.Claims.ClaimValueTypes.Integer32);
                    }
                    else 
                    {

                        netRegisteredClaim = new System.Security.Claims.Claim(registeredClaim.getKey(), registeredClaim.getValue());
                    }

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

        private bool verifyPrivateClaims(JwtSecurityToken jwtToken, PrivateClaims privateClaims, JWTOptions options)
        {
            RegisteredClaims registeredClaims = options.getAllRegisteredClaims();
            PublicClaims publicClaims = options.getAllPublicClaims();
            if (privateClaims == null || privateClaims.isEmpty())
            {
                return true;
            }
            string jsonPayload = jwtToken.Payload.SerializeToJson();
            Dictionary<string, object> map = null;
            try
            {
                map = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonPayload);
            }
            catch (Exception)
            {
                this.error.setError("JW009", "Cannot parse JWT payload");
                return false;
            }
            this.counter = 0;
            bool validation = verifyNestedClaims(privateClaims.getNestedMap(), map, registeredClaims, publicClaims);
            int pClaimsCount = countingPrivateClaims(privateClaims.getNestedMap(), 0);
            if (validation && !(this.counter == pClaimsCount))
            {
                return false;
            }
            return validation;
        }

        private bool verifyNestedClaims(Dictionary<string, object> pclaimMap, Dictionary<string, object> map,
                    RegisteredClaims registeredClaims, PublicClaims publicClaims)
        {
            List<string> mapClaimKeyList = new List<string>(map.Keys);
            List<string> pClaimKeyList = new List<string>(pclaimMap.Keys);
            if (pClaimKeyList.Count > pClaimKeyList.Count)
            {
                return false;
            }
            foreach (String mapKey in mapClaimKeyList)
            {

                if (!isRegistered(mapKey, registeredClaims) && !isPublic(mapKey, publicClaims))
                {
                    this.counter++;
                    if (!pclaimMap.ContainsKey(mapKey))
                    {
                        return false;
                    }

                    object op = pclaimMap[mapKey];
                    object ot = map[mapKey];

                    if ((op.GetType() == typeof(string)) && (ot.GetType() == typeof(string)))
                    {

                        if (!SecurityUtils.compareStrings(((string)op).Trim(), ((string)ot).Trim()))
                        {
                            return false;
                        }
                    }
                    else if ((op.GetType() == typeof(Dictionary<string, object>)) && (ot.GetType() == typeof(JObject)))
                    {


                        bool flag = verifyNestedClaims((Dictionary<string, object>)op, ((JObject)ot).ToObject<Dictionary<string, object>>(),
                                registeredClaims, publicClaims);
                        if (!flag)
                        {
                            return false;
                        }
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        private void AddHeaderParameters(JwtHeader header, JWTOptions options)
        {
            HeaderParameters parameters = options.GetHeaderParameters();
            List<string> list = parameters.GetAll();
            Dictionary<string, object> map = parameters.GetMap();
            foreach (string s in list)
            {
                header.Add(s.Trim(), ((string)map[s]).Trim());
            }
        }

        private bool VerifyHeader(JwtSecurityToken jwtToken, JWTOptions options)
        {
            HeaderParameters parameters = options.GetHeaderParameters();
            if (parameters.IsEmpty())
            {
                return true;
            }

            List<String> allParms = parameters.GetAll();
            if (jwtToken.Header.Count != allParms.Count + 2)
            {
                return false;
            }
            Dictionary<String, Object> map = parameters.GetMap();


            foreach (string s in allParms)
            {

                if (!jwtToken.Header.ContainsKey(s.Trim()))
                {
                    return false;
                }


                string claimValue = null;
                try
                {
                    claimValue = (string)jwtToken.Header[s.Trim()];
                }
                catch (Exception)
                {
                    return false;
                }
                String optionsValue = ((string)map[s]).Trim();
                if (!SecurityUtils.compareStrings(claimValue, optionsValue.Trim()))
                {
                    return false;
                }
            }
            return true;

        }

        private bool isRegistered(string claimKey, RegisteredClaims registeredClaims)
        {

            List<Claim> registeredClaimsList = registeredClaims.getAllClaims();
            foreach (Claim s in registeredClaimsList)
            {
                if (SecurityUtils.compareStrings(s.getKey().Trim(), claimKey.Trim()))
                {
                    return true;
                }
            }
            return false;
        }

        private bool isPublic(string claimKey, PublicClaims publicClaims)
        {
            List<Claim> publicClaimsList = publicClaims.getAllClaims();
            foreach (Claim s in publicClaimsList)
            {
                if (SecurityUtils.compareStrings(s.getKey().Trim(), claimKey.Trim()))
                {
                    return true;
                }
            }
            return false;
        }

        private int countingPrivateClaims(Dictionary<string, object> map, int counter)
        {
            List<string> list = new List<string>(map.Keys);
            foreach (string s in list)
            {
                counter++;
                object obj = map[s];
                if (obj.GetType() == typeof(Dictionary<string, object>))
                {
                    counter = countingPrivateClaims((Dictionary<string, object>)obj, counter);
                }
            }
            return counter;
        }
    }
}


