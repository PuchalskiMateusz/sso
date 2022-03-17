using System;
using System.Security.Cryptography;
using System.Text;

namespace SSO.Services
{
    public class SsoService
    {
        public Byte[] GenerateHmac(string text, string secretKey)
        {
            var encoding = new ASCIIEncoding();

            var textBytes = Encoding.Default.GetBytes(text);
            var keyBytes = Encoding.Default.GetBytes(secretKey);


            using var hash = new HMACSHA256(keyBytes);
            var hashBytes = hash.ComputeHash(textBytes);

            return hashBytes;
        }
    }
}