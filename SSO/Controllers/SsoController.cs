using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using SSO.Services;

namespace SSO.Controllers
{
    public class SsoController : Controller
    {
        private IConfiguration _configuration;
        private readonly SsoService _ssoService;

        public SsoController(IConfiguration configuration, SsoService ssoService)
        {
            _configuration = configuration;
            _ssoService = ssoService;
        }
        public IActionResult Commento(string token, string hmac)
        {
            string secretKey = _configuration.GetValue<string>("CommentoSecretKey");

            var bHmac= Encoding.Default.GetBytes(hmac);
            var expectedHmac = _ssoService.GenerateHmac(token, secretKey);
            
            if  (bHmac != expectedHmac)
                return Forbid();


            var payload = 
                new { token = token, 
                    email = HttpContext.User.Identity.Name, 
                    name = HttpContext.User.Identity.Name };

            var hmacPayload = _ssoService.GenerateHmac(Newtonsoft.Json.JsonConvert.SerializeObject(payload), secretKey);

            var newHmac = BitConverter.ToString(hmacPayload).Replace("-", "");
            var bPayload = Encoding.Default.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(payload));
            var hexPayload = BitConverter.ToString(bPayload).Replace("-", "");

            return Redirect("https://commento.io/api/oauth/sso/callback?payload=" + hexPayload + "&hmac=" + newHmac);
        }

        
    }
}
