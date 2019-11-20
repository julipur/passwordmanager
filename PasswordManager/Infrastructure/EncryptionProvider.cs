using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using PasswordManager.Infrastructure.Contracts;

namespace PasswordManager.Infrastructure
{
    public class EncryptionProvider : IEncryptionProvider
    {
        public void Generate(string fileName, string identity, string password)
        {
            if (File.Exists($@"keys\{fileName}.pkr"))
                return;

            var generateKeyRing = GenerateKeyRing(identity, password);

            Directory.CreateDirectory("keys");

            var pkr = generateKeyRing.GeneratePublicKeyRing();
            var publicKeyStream = new BufferedStream(new FileStream($@"keys\{fileName}.pkr", System.IO.FileMode.Create));
            pkr.Encode(publicKeyStream);
            publicKeyStream.Close();

            // Generate private key, dump to file.
            var skr = generateKeyRing.GenerateSecretKeyRing();
            var secretKeyStream = new BufferedStream(new FileStream($@"keys\{fileName}.skr", System.IO.FileMode.Create));
            skr.Encode(secretKeyStream);
            secretKeyStream.Close();

        }

        public bool Encrypt(string fileToEncrypt)
        {
            var publicKeyFiles = Directory.GetFiles(@"keys", "*.pkr");
            var privateKeyFiles = Directory.GetFiles(@"keys", "*.skr");

            if (publicKeyFiles.Length == 0 || privateKeyFiles.Length == 0)
            {
                Console.Write("There are no key files generated. Generate by using the keygen command.");
                return false;
            }

            var publicKey = publicKeyFiles[0];
            var privateKey = privateKeyFiles[0];

            var pgp = new PGPEncryptionHelper();
            pgp.Encrypt(fileToEncrypt, publicKey, $"");
            return true;
        }

        public void Decrypt(string fileToDecrypt, string passPhrase)
        {
            var publicKeyFiles = Directory.GetFiles(@"keys", "*.pkr");
            var privateKeyFiles = Directory.GetFiles(@"keys", "*.skr");

            if (publicKeyFiles.Length == 0 || privateKeyFiles.Length == 0)
            {
                Console.Write("There are no key files generated. Generate by using the keygen command.");
                return;
            }
            
            var privateKey = privateKeyFiles[0];

            var pgp = new PGPEncryptionHelper();
            pgp.Decrypt(fileToDecrypt, privateKey, passPhrase, "" );
        }

        public static PgpKeyRingGenerator GenerateKeyRing(string identity, string password)
        {

            var keyRingParams = new KeyRingParams
            {
                Password = password,
                Identity = identity,
                PrivateKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTag.Aes128,
                SymmetricAlgorithms =
                    new SymmetricKeyAlgorithmTag[]
                    {
                        SymmetricKeyAlgorithmTag.Aes256, SymmetricKeyAlgorithmTag.Aes192,
                        SymmetricKeyAlgorithmTag.Aes128
                    },
                HashAlgorithms = new HashAlgorithmTag[]
                {
                    HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha1, HashAlgorithmTag.Sha384,
                    HashAlgorithmTag.Sha512, HashAlgorithmTag.Sha224,
                }
            };


            var generator = GeneratorUtilities.GetKeyPairGenerator("RSA");
            generator.Init(keyRingParams.RsaParams);

            /* Create the master (signing-only) key. */
            var masterKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaSign, generator.GenerateKeyPair(), DateTime.UtcNow);

            var masterSubpckGen = new PgpSignatureSubpacketGenerator();
            masterSubpckGen.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
            masterSubpckGen.SetPreferredSymmetricAlgorithms(false,
                (from a in keyRingParams.SymmetricAlgorithms
                 select (int)a).ToArray());
            masterSubpckGen.SetPreferredHashAlgorithms(false,
                (from a in keyRingParams.HashAlgorithms
                 select (int)a).ToArray());

            /* Create a signing and encryption key for daily use. */
            var encKeyPair = new PgpKeyPair(
                PublicKeyAlgorithmTag.RsaGeneral,
                generator.GenerateKeyPair(),
                DateTime.UtcNow);

            var encSubpckGen = new PgpSignatureSubpacketGenerator();
            encSubpckGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

            masterSubpckGen.SetPreferredSymmetricAlgorithms(false,
                (from a in keyRingParams.SymmetricAlgorithms
                 select (int)a).ToArray());
            masterSubpckGen.SetPreferredHashAlgorithms(false,
                (from a in keyRingParams.HashAlgorithms
                 select (int)a).ToArray());

            /* Create the key ring. */
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                masterKeyPair,
                keyRingParams.Identity,
                keyRingParams.PrivateKeyEncryptionAlgorithm.Value,
                keyRingParams.GetPassword(),
                true,
                masterSubpckGen.Generate(),
                null,
                new SecureRandom());

            /* Add encryption subkey. */
            keyRingGen.AddSubKey(encKeyPair, encSubpckGen.Generate(), null);

            return keyRingGen;
        }
    }

    internal class KeyRingParams
    {

        public SymmetricKeyAlgorithmTag? PrivateKeyEncryptionAlgorithm { get; set; }
        public SymmetricKeyAlgorithmTag[] SymmetricAlgorithms { get; set; }
        public HashAlgorithmTag[] HashAlgorithms { get; set; }
        public RsaKeyGenerationParameters RsaParams { get; set; }
        public string Identity { get; set; }
        public string Password { get; set; }
        //= EncryptionAlgorithm.NULL;

        public char[] GetPassword()
        {
            return Password.ToCharArray();
        }

        public KeyRingParams()
        {
            //Org.BouncyCastle.Crypto.Tls.EncryptionAlgorithm
            RsaParams = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 12);
        }

    }
}