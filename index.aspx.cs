using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using SecureCookie.util;
using SecureCookie.cookie;

namespace SecureCookie
{
    public partial class index : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

            Utils utils = new Utils();
            InsecureCookieProtocol insecure = new InsecureCookieProtocol();
            FuCookieProtocol fu = new FuCookieProtocol();
            OtherCookieProtocol other = new OtherCookieProtocol();
            OurCookieProtocol our = new OurCookieProtocol();

            

           
            Label1.Text = "Fu's cookie creation time = " + utils.calculateAverage("fu_cookie_creation_times").ToString() + "<br/>"
                + "Fu's cookie verification time = " + utils.calculateAverage("fu_cookie_verification_times").ToString() + "<br/>"
                + "Other cookie creation time = " + utils.calculateAverage("other_cookie_creation_times").ToString() + "<br/>"
                + "Other cookie verification time = " + utils.calculateAverage("other_cookie_verification_times").ToString() + "<br/>"
                + "Our cookie creation time = " + utils.calculateAverage("our_cookie_creation_times").ToString() + "<br/>"
                + "Our cookie verification time = " + utils.calculateAverage("our_cookie_verification_times").ToString() + "<br/>"
                + "Insecure cookie creation time = " + utils.calculateAverage("Insecure_cookie_creation_times").ToString() + "<br/>"
                + "Insecure cookie verification time = " + utils.calculateAverage("Insecure_cookie_verification_times").ToString() + "<br/>"
                ;

           


            /*

            HttpCookie cc = insecure.create();
            HttpCookie fucookie = fu.create();
            HttpCookie othercookie = other.create();
            HttpCookie ourcookie = our.create();

            insecure.verification(Request.Cookies["InsecureCookieProtocol"]);
            fu.verification(Request.Cookies["FuCookieProtocol"]);
            other.verification(Request.Cookies["OtherCookieProtocol"]);
            our.verification(Request.Cookies["OurCookieProtocol"]);
            */
        }
    }
}