using SecureCookie.util;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Web;

namespace SecureCookie.cookie
{
    public class InsecureCookieProtocol
    {
        private Stopwatch clock;
        private Utils utils = new Utils();

        public HttpCookie create()
        {
            //stop watch for calculating elapsed time
            clock = new Stopwatch();
            clock.Start();
            HttpCookie cookie = new HttpCookie("InsecureCookieProtocol");
            StringBuilder cookieContent = new StringBuilder();

            //set cookie expiration date to 7 days later
            DateTime expiresDate = DateTime.Now.AddDays(7);

            //create cookie content
            cookieContent.Append(Utils.USERNAME);
            cookieContent.Append("|");
            cookieContent.Append(expiresDate.ToString());
            cookieContent.Append("|");
            cookieContent.Append(Utils.DATA);

            cookie.Expires = expiresDate;
            cookie.Value = cookieContent.ToString();

            clock.Stop();
            utils.addResult("insecure_cookie_creation_times", clock.Elapsed.TotalMilliseconds);
            return cookie;
        }

        public Boolean verification(HttpCookie cookie)
        {
            //stop watch for calculating elapsed time
            clock = new Stopwatch();
            clock.Start();

            string cookieContent = cookie.Value;
            string[] splited = cookieContent.Split('|');
            string username = splited[0];
            string expirationDateString = splited[1];
            string data = splited[2];
            DateTime expirationDate = DateTime.Parse(expirationDateString);

            //check expiration date
            if (expirationDate.CompareTo(DateTime.Now) <= 0)
            {
                return false;
            }
            clock.Stop();
            utils.addResult("insecure_cookie_verification_times", clock.Elapsed.TotalMilliseconds);
            return true;
        }
    }
}