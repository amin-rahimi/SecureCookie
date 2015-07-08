using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Diagnostics;
namespace SecureCookie.util
{
    public class Utils
    {

        private readonly Random random = new Random();
        private const string chars = "qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM";

        //sample server key
        public static string SERVER_KEY = "a2CdFd47t#lnDv*yDjh710S7HbdD7d6!";

        //sample username
        public static string USERNAME = "admin";

        //sample cookie data
        public static string DATA = "money=100000000;vip=true";

        //generate hmac code
        public String HMAC(String data, String key)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();

            //using hmach sha1 for hashing
            HMACSHA1 hmach_sha1 = new HMACSHA1(encoding.GetBytes(key));

            byte[] encrypted = hmach_sha1.ComputeHash(encoding.GetBytes(data));

            return ByteToString(encrypted);

        }

        //convert bytes to string
        private string ByteToString(byte[] buff)
        {
            string sbinary = "";

            for (int i = 0; i < buff.Length; i++)
            {
                sbinary += buff[i].ToString("X2"); // hex format
            }
            return (sbinary);
        }

        public void addResult(string name, double totalMiliSeconds)
        {
            //create report file in server path
            string path = HttpContext.Current.Server.MapPath("~") + "\\" + name + ".txt";

            if (totalMiliSeconds < 0.03)
            {
                //add result to the end of the file
                File.AppendAllText(path, Convert.ToString(totalMiliSeconds) + Environment.NewLine);
            }

        }

        public double calculateAverage(string name)
        {
            string path = HttpContext.Current.Server.MapPath("~") + "\\" + name + ".txt";
            string[] lines = File.ReadAllLines(path);
            double sum = 0;
            int count = 0;
            foreach (string line in lines)
            {
                if (!line.Equals(""))
                {
                    sum += Convert.ToDouble(line);
                    count++;
                }
            }
            return sum/count;
        }

        //generate guid for uniqe keys
        public string getGUID()
        {
            Stopwatch watch = new Stopwatch();
            watch.Start();
            Guid guid = Guid.NewGuid();
            watch.Stop();
            return guid.ToString();

        }
    }
}