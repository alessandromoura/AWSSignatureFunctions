using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using System.Security.Cryptography;
using System.Text;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Globalization;
using Newtonsoft.Json;
using Amazon.Runtime.CredentialManagement;
using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using System.Net.Http.Headers;
using System.Web.Http;
using System.Runtime.Caching;

namespace AlessandroMoura
{
    public static class CreateAuthorizationSignature
    {
        public const string ISO8601BasicFormat = "yyyyMMddTHHmmssZ";
        public const string DateStringFormat = "yyyyMMdd";
        public const string TERMINATOR = "aws4_request";
        public const string REGION = "ap-southeast-2";
        public const string SERVICE = "execute-api";

        static MemoryCache memoryCache = MemoryCache.Default;

        [FunctionName("CreateAuthorizationSignature")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("C# HTTP trigger started for CreateAuthorizationSignature.");

            try
            {
                string jsonContent = await req.Content.ReadAsStringAsync();

                // 1. Prepare variables
                var requestDateTime = DateTime.UtcNow;
                var dateTimeStamp = requestDateTime.ToString(ISO8601BasicFormat, CultureInfo.InvariantCulture);
                var dateStamp = requestDateTime.ToString(DateStringFormat, CultureInfo.InvariantCulture);

                string awsApiKey = "";
                string awsGatewayApiUri = "";
                string awsAccessKey = "";
                string awsSecretAccessKey;
                string awsAccountId = "";
                string awsRoleName = "";
                int awsTokenDuration = 900;

                // 2. Read values from the Header
                try
                {
                    awsApiKey = GetHeader(req.Headers, "AWSApiKey");
                    awsGatewayApiUri = GetHeader(req.Headers, "AWSGatewayApiUri");
                    awsAccessKey = GetHeader(req.Headers, "AWSAccessKey");
                    awsSecretAccessKey = GetHeader(req.Headers, "AWSSecretAccessKey");
                    awsAccountId = GetHeader(req.Headers, "AWSAccountId");
                    awsRoleName = GetHeader(req.Headers, "AWSRoleName");
                    awsTokenDuration = int.Parse(GetHeader(req.Headers, "AWSTokenDuration"));
                }
                catch (Exception ex)
                {
                    HttpResponseMessage httpResponse = new HttpResponseMessage(HttpStatusCode.BadRequest);
                    httpResponse.ReasonPhrase = string.Format("Please specify all required headers for this request. {0}", ex.Message);
                    throw new HttpResponseException(httpResponse);
                }

                // 3. Get Token Authentication Keys
                TokenAuthenticationKeys token = GetAuthenticationKeys(awsAccountId, awsRoleName, awsAccessKey, awsSecretAccessKey, awsTokenDuration);

                // 3. Compute Hash of the request body
                HashAlgorithm hash = HashAlgorithm.Create("SHA-256");
                byte[] contentHash = hash.ComputeHash(Encoding.UTF8.GetBytes(jsonContent));
                string contenthHashString = ToHexString(contentHash, true);

                // 4. Create the headers
                var headers = new Dictionary<string, string>();
                headers.Add("host", new Uri(awsGatewayApiUri).Host);
                headers.Add("content-type", "application/json");
                headers.Add("x-amz-date", dateTimeStamp);
                headers.Add("x-api-key", awsApiKey);
                headers.Add("content-length", jsonContent.Length.ToString());
                headers.Add("x-amz-security-token", token.SessionToken);

                // 5. Canonicalize Request
                var canonicalRequest = CanonicalizeRequest(req.Method.ToString(), new Uri(awsGatewayApiUri), headers, contenthHashString);

                // 6. Compute hash of the canonical request
                byte[] canonicalRequestHash = hash.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest));
                string canonicalRequestHashString = ToHexString(canonicalRequestHash, true);

                log.Info(string.Format("Canonical String: {0}", canonicalRequest));
                log.Info(string.Format("Canonical Hash: {0}", canonicalRequestHashString));

                // 7. Construct string to be signed
                string scope = string.Format("{0}/{1}/{2}/{3}",
                                             dateStamp,
                                             REGION,
                                             SERVICE,
                                             TERMINATOR);

                StringBuilder stringToSign = new StringBuilder();
                stringToSign.AppendFormat("{0}\n", "AWS4-HMAC-SHA256");
                stringToSign.AppendFormat("{0}\n", dateTimeStamp);
                stringToSign.AppendFormat("{0}\n", scope);
                stringToSign.AppendFormat("{0}", canonicalRequestHashString);

                log.Info(string.Format("String to Sign: {0}", stringToSign.ToString()));

                // 8. Compute the signing key
                var kha = KeyedHashAlgorithm.Create("HMACSHA256");
                kha.Key = DeriveSigningKey("HmacSHA256", token.SessionSecretAccessKey, REGION, dateStamp, SERVICE);

                // 9. Compute the AWS4 signature
                var signature = kha.ComputeHash(Encoding.UTF8.GetBytes(stringToSign.ToString()));
                var signatureString = ToHexString(signature, true);

                // 10. Create the authentication string
                var authString = new StringBuilder();
                authString.AppendFormat("AWS4-HMAC-SHA256 ");
                authString.AppendFormat("Credential={0}/{1}, ", token.SessionAccessKey, scope);
                authString.AppendFormat("SignedHeaders={0}, ", CanonicalizeHeaderNames(headers));
                authString.AppendFormat("Signature={0}", signatureString);

                Response response = new Response
                {
                    DateTimeStamp = dateTimeStamp,
                    Signature = authString.ToString(),
                    SessionToken = token.SessionToken
                };

                return req.CreateResponse(HttpStatusCode.OK, response);
            }
            catch (Amazon.SecurityToken.AmazonSecurityTokenServiceException ex)
            {
                return req.CreateResponse(ex.StatusCode, ex.Message);
            }
            catch (HttpResponseException ex)
            {
                return req.CreateResponse(ex.Response.StatusCode, ex.Response.ReasonPhrase);
            }
            catch (Exception ex)
            {
                return req.CreateErrorResponse(System.Net.HttpStatusCode.InternalServerError, ex.Message);
            }

        }

        private static byte[] DeriveSigningKey(string algorithm, string awsSecretAccessKey, string region, string date, string service)
        {
            byte[] ksecret = Encoding.UTF8.GetBytes(("AWS4" + awsSecretAccessKey).ToCharArray());
            byte[] hashDate = ComputeKeyedHash(algorithm, ksecret, date);
            byte[] hashRegion = ComputeKeyedHash(algorithm, hashDate, region);
            byte[] hashService = ComputeKeyedHash(algorithm, hashRegion, service);

            return ComputeKeyedHash(algorithm, hashService, TERMINATOR);
        }

        private static byte[] ComputeKeyedHash(string algorithm, byte[] key, string data)
        {
            var kha = KeyedHashAlgorithm.Create(algorithm);
            kha.Key = key;
            return kha.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static string CanonicalizeRequest(string httpMethod, Uri endpoint, IDictionary<string, string> headers, string precomputedBodyHash)
        {
            var canonicalRequest = new StringBuilder();
            canonicalRequest.AppendFormat("{0}\n", httpMethod);
            canonicalRequest.AppendFormat("{0}\n", endpoint.AbsolutePath);
            canonicalRequest.AppendFormat("{0}\n", string.Empty); //Placeholder for QueryString (Not necessary in this scenario)
            canonicalRequest.AppendFormat("{0}\n", CanonicalizeHeaders(headers));
            canonicalRequest.AppendFormat("{0}\n", CanonicalizeHeaderNames(headers));
            canonicalRequest.Append(precomputedBodyHash);

            return canonicalRequest.ToString();
        }

        private static string CanonicalizeHeaders(IDictionary<string, string> headers)
        {
            if (headers == null || headers.Count() == 0)
            {
                return string.Empty;
            }

            var builder = new StringBuilder();

            foreach (var item in headers.OrderBy(kvp => kvp.Key.ToLowerInvariant()))
            {
                builder.Append(item.Key.ToLowerInvariant());
                builder.Append(":");
                builder.Append(CompressSpaces(item.Value));
                builder.Append("\n");
            }

            return builder.ToString();
        }

        private static string CanonicalizeHeaderNames(IDictionary<string, string> headers)
        {
            var headersToSign = new List<string>(headers.Keys);
            headersToSign.Sort(StringComparer.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            foreach (var item in headersToSign)
            {
                if (sb.Length > 0)
                {
                    sb.Append(";");
                }
                sb.Append(item.ToLower());
            }

            return sb.ToString();
        }

        private static string CompressSpaces(string data)
        {
            if (data == null || !data.Contains(" "))
            {
                return data;
            }

            var compressed = new Regex("\\s+").Replace(data, " ");
            return compressed;
        }

        private static string ToHexString(byte[] data, bool lowercase)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2"));
            }
            return sb.ToString();
        }

        private static string GetHeader(HttpRequestHeaders headers, string key)
        {
            try
            {
                return headers.GetValues(key).First();
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Header '{0}' not present in the request.", key), ex);
            }
        }

        /// <summary>
        /// This method will extract a session authentication token from AWS for consumption when calling the API gateway
        /// </summary>
        /// <param name="awsAccountId"></param>
        /// <param name="awsRoleName"></param>
        /// <param name="awsAccessKey"></param>
        /// <param name="awsSecretAccessKey"></param>
        /// <param name="tokenDuration"></param>
        /// <returns></returns>
        public static TokenAuthenticationKeys GetAuthenticationKeys(string awsAccountId, string awsRoleName, string awsAccessKey, string awsSecretAccessKey, int tokenDuration = 900)
        {
            TokenAuthenticationKeys token = null;

            var cacheObject = memoryCache["sessionToken"];
            if (cacheObject == null)
            {
                Amazon.SecurityToken.AmazonSecurityTokenServiceClient client = new AmazonSecurityTokenServiceClient(awsAccessKey, awsSecretAccessKey);
                var stsResponse = client.AssumeRole(new AssumeRoleRequest
                {
                    DurationSeconds = tokenDuration,
                    ExternalId = string.Format("Dynamics365ToESB_{0}", DateTime.UtcNow.ToString("yyyyMMddHHmmssZ")),
                    RoleArn = string.Format("arn:aws:iam::{0}:role/{1}", awsAccountId, awsRoleName),
                    RoleSessionName = "Dynamics365ToESB"
                });
                token = new TokenAuthenticationKeys()
                {
                    SessionAccessKey = stsResponse.Credentials.AccessKeyId,
                    SessionSecretAccessKey = stsResponse.Credentials.SecretAccessKey,
                    SessionToken = stsResponse.Credentials.SessionToken
                };

                memoryCache.Set("sessionToken", token, DateTimeOffset.Now.AddSeconds(tokenDuration));
            }
            else
            {
                token = (TokenAuthenticationKeys)cacheObject;
            }

            return token;
        }
    }

    public class Response
    {
        public string DateTimeStamp;
        public string Signature;
        public string SessionToken;
    }

    public class TokenAuthenticationKeys
    {
        public string SessionAccessKey;
        public string SessionSecretAccessKey;
        public string SessionToken;
    }

    public class HttpException : Exception
    {

    }

}
