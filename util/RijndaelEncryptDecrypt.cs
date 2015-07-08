using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.IO;

namespace SecureCookie.util
{
    public class RijndaelEncryptDecrypt
    {

        //encrypt array of bytes
        private byte[] encrypt(byte[] plainText, byte[] key, byte[] IV)
        {
            MemoryStream stream = new MemoryStream();
            Rijndael rijndael = Rijndael.Create();
            rijndael.Key = key;
            rijndael.IV = IV;
            CryptoStream cryptoStream = new CryptoStream(stream, rijndael.CreateEncryptor(rijndael.Key, rijndael.IV), CryptoStreamMode.Write);
            cryptoStream.Write(plainText, 0, plainText.Length);
            cryptoStream.Close();
            byte[] encrypted = stream.ToArray();
            return encrypted;
        }

        //decrypt array of bytes
        private byte[] decrypt(byte[] encryptedText, byte[] key, byte[] IV)
        {
            MemoryStream stream = new MemoryStream();
            Rijndael rijndael = Rijndael.Create();
            rijndael.Key = key;
            rijndael.IV = IV;
            CryptoStream cryptoStream = new CryptoStream(stream, rijndael.CreateDecryptor(rijndael.Key, rijndael.IV), CryptoStreamMode.Write);
            cryptoStream.Write(encryptedText, 0, encryptedText.Length);
            cryptoStream.Close();
            byte[] decrypted = stream.ToArray();
            return decrypted;

        }

        //return rijndael encrypted string
        public String encrypt(String plainText, String key)
        {
            byte[] plainTextBytes = System.Text.Encoding.Unicode.GetBytes(plainText);
            PasswordDeriveBytes pwdBytes = new PasswordDeriveBytes(key, new byte[] { 0x10, 0x40, 0x00, 0x34, 0x1A, 0x70, 0x01, 0x34, 0x56, 0xFF, 0x99, 0x77, 0x4C, 0x22, 0x49 });
            byte[] encrypted = encrypt(plainTextBytes, pwdBytes.GetBytes(32), pwdBytes.GetBytes(16));
            return Convert.ToBase64String(encrypted);
        }

        //decrypt string
        public String decrypt(String encryptedText, String key)
        {
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            PasswordDeriveBytes pwdBytes = new PasswordDeriveBytes(key, new byte[] { 0x10, 0x40, 0x00, 0x34, 0x1A, 0x70, 0x01, 0x34, 0x56, 0xFF, 0x99, 0x77, 0x4C, 0x22, 0x49 });
            byte[] decrypted = decrypt(encryptedBytes, pwdBytes.GetBytes(32), pwdBytes.GetBytes(16));
            return System.Text.Encoding.Unicode.GetString(decrypted);
        }
    }
}