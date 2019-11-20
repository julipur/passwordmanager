using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PasswordManager.Infrastructure.Contracts;

namespace PasswordManager.Infrastructure
{
    public class PasswordManager : IPasswordManager
    {
        private readonly IEncryptionProvider _encryptionProvider;

        public PasswordManager(IEncryptionProvider encryptionProvider)
        {
            _encryptionProvider = encryptionProvider;
        }

        public void Import(string fileToEncrypt)
        {
            if (!File.Exists(fileToEncrypt))
            {
                Console.WriteLine($"The file: {fileToEncrypt} does not exist.");
                return;
            }

            var success = _encryptionProvider.Encrypt(fileToEncrypt);

            if (success)
            {
                File.Delete(fileToEncrypt);
                Console.WriteLine($"successfully imported passwords from {fileToEncrypt}");
            }
        }

        public void GetPassword(string key, string passPhrase)
        {
            _encryptionProvider.Decrypt("passwords.asc", passPhrase);

            var rows = File.ReadAllLines("passwords.csv");

            foreach (var row in rows)
            {
                var array = row.Split(',');
                if (array[0].IndexOf(key, StringComparison.CurrentCultureIgnoreCase) > -1)
                    Console.WriteLine(row);
            }

            File.Delete("passwords.csv");

        }

        public void Decrypt(string passPhrase)
        {
            _encryptionProvider.Decrypt("passwords.asc", passPhrase);
        }
    }
}
