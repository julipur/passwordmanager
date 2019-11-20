namespace PasswordManager.Infrastructure.Contracts
{
    public interface IEncryptionProvider
    {
        void Generate(string fileName, string identity, string password);
        bool Encrypt(string fileToEncrypt);
        void Decrypt(string fileToDecrypt, string passPhrase);
    }
}