using SecureCookie.util;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Web;

namespace SecureCookie.cookie
{
    public class OtherCookieProtocol
    {
        private Stopwatch clock;
        private Utils utils = new Utils();
        private RijndaelEncryptDecrypt rijndael = new RijndaelEncryptDecrypt();

        public HttpCookie create()
        {
            //stop watch for calculating elapsed time
            clock = new Stopwatch();
            clock.Start();

            HttpCookie cookie = new HttpCookie("OtherCookieProtocol");
            StringBuilder cookieContent = new StringBuilder();

            //set cookie expiration date to 7 days later
            DateTime expiresDate = DateTime.Now.AddDays(7);

            //create cookie content
            cookieContent.Append(Utils.USERNAME);
            cookieContent.Append("|");
            cookieContent.Append(expiresDate.ToString());
            cookieContent.Append("|");
            string key = utils.HMAC(Utils.USERNAME + "|" + expiresDate.ToString(), Utils.SERVER_KEY);
            cookieContent.Append(rijndael.encrypt(Utils.DATA, key));
            cookieContent.Append("|");
            cookieContent.Append(utils.HMAC(Utils.USERNAME + "|" + expiresDate.ToString() + "|" + Utils.DATA, key));
            cookie.Expires = expiresDate;
            cookie.Value = cookieContent.ToString();

            clock.Stop();
            utils.addResult("other_cookie_creation_times", clock.Elapsed.TotalMilliseconds);
            return cookie;
        }

        public Boolean verification(HttpCookie cookie)
        {
            clock = new Stopwatch();
            clock.Start();
            string cookieContent = cookie.Value;

            //split cookie content by |
            //get values from splited array
            string[] splited = cookieContent.Split('|');
            string username = splited[0];
            string expirationDateString = splited[1];
            DateTime expirationDate = DateTime.Parse(expirationDateString);

            //check expiration date
            if (expirationDate.CompareTo(DateTime.Now) <= 0)
            {
                return false;
            }
            string encryptedData = splited[2];
            string hmacEncryptedData = splited[3];
            string key = utils.HMAC(username + "|" + expirationDateString, Utils.SERVER_KEY);
            string plainData = rijndael.decrypt(encryptedData, key);

            //create hmac for cookie values
            string hmacDataFromCookie = username + "|" + expirationDateString + "|" + plainData;
            string calculatedEncryptedHmacData = utils.HMAC(hmacDataFromCookie, key);

            //check for cookie content change
            if (calculatedEncryptedHmacData.CompareTo(hmacEncryptedData) != 0)
            {
                return false;
            }
            clock.Stop();
            utils.addResult("other_cookie_verification_times", clock.Elapsed.TotalMilliseconds);
            return true;
        }
    }
}