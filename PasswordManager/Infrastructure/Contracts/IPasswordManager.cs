namespace PasswordManager.Infrastructure.Contracts
{
    public interface IPasswordManager
    {
        void Import(string fileToEncrypt);
        void GetPassword(string key, string passPhrase);
        void Decrypt(string passPhrase);
    }
}