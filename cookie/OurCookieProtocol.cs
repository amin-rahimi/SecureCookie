using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Web;
using SecureCookie.util;

namespace SecureCookie.cookie
{
    public class OurCookieProtocol
    {
        private Stopwatch clock;
        private Utils utils = new Utils();
        private RijndaelEncryptDecrypt rijndael = new RijndaelEncryptDecrypt();

        public HttpCookie create()
        {
            clock = new Stopwatch();
            clock.Start();

            HttpCookie cookie = new HttpCookie("OurCookieProtocol");
            StringBuilder cookieContent = new StringBuilder();

            //set cookie expiration date to 7 days later
            DateTime expiresDate = DateTime.Now.AddDays(7);

            //create cookie content
            //insert user unique string guid
            string guidDtring = utils.getGUID();
            cookieContent.Append(guidDtring);
            cookieContent.Append("|");

            //create dynamic key for encrypt the data
            string key = utils.HMAC(guidDtring, Utils.SERVER_KEY);

            //encrypt (data|username|expiration time)
            string dataArray = Utils.DATA + "|" + Utils.USERNAME + "|" + expiresDate.ToString();
            cookieContent.Append(rijndael.encrypt(dataArray, key));
            cookieContent.Append("|");
            //create hmac(guid|data|username|expiration date|[session id])
            //session id for ssl connections session id
            cookieContent.Append(utils.HMAC(guidDtring + "|" + dataArray, key));
            cookie.Expires = expiresDate;
            cookie.Value = cookieContent.ToString();

            clock.Stop();
            utils.addResult("our_cookie_creation_times", clock.Elapsed.TotalMilliseconds);
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
            string guidString = splited[0];
            string encryptedData = splited[1];
            //generate key for decrypt data
            string key = utils.HMAC(guidString, Utils.SERVER_KEY);
            //decrypt
            string plainData = rijndael.decrypt(encryptedData, key);
            string hmacEncryptedData = splited[2];
            //create hmac for cookie values
            string hmacDataFromCookie = guidString + "|" + plainData;
            string calculatedEncryptedHmacData = utils.HMAC(hmacDataFromCookie, key);

            //check for cookie content change
            if (calculatedEncryptedHmacData.CompareTo(hmacEncryptedData) != 0)
            {
                return false;
            }

            //split data field (data|expiration time)
            string[] dataSplited = plainData.Split('|');
            string data = dataSplited[0];
            string username = dataSplited[1];
            string expirationDateString = dataSplited[2];
            DateTime expirationDate = DateTime.Parse(expirationDateString);

            //check expiration date
            if (expirationDate.CompareTo(DateTime.Now) <= 0)
            {
                return false;
            }

            clock.Stop();
            utils.addResult("our_cookie_verification_times", clock.Elapsed.TotalMilliseconds);
            return true;
        }
    }
}