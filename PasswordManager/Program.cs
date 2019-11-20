using System;
using System.IO;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PasswordManager.Infrastructure;

namespace PasswordManager
{
    class Program
    {
        public static int Main(string[] args)
        {
            var app = new CommandLineApplication
            {
                Name = "pm",
                Description = "Personal password manager",
            };

            app.HelpOption(inherited: true);

            app.Command("keygen", keyGenCmd =>
            {
                keyGenCmd.Description = "Generate new PGP key pair";
                var fileName = keyGenCmd.Argument("file", "Name of the generated key pair file. ").IsRequired();
                var identity = keyGenCmd.Argument("identity", "Identity for the PGP Key Ring.").IsRequired();
                var password = keyGenCmd.Argument("password", "Password for the PGP KeyRing.").IsRequired();
                keyGenCmd.OnExecute(() =>
                {
                    new EncryptionProvider().Generate(fileName.Value, identity.Value, password.Value);
                    Console.WriteLine("Generating public/private key pair.");
                });
            });


            app.Command("import", importCmd =>
            {
                importCmd.Description = "Imports a password file.";
                var file = importCmd.Argument("file", "Name of the file").IsRequired();
                importCmd.OnExecute(() =>
                {
                    new Infrastructure.PasswordManager(new EncryptionProvider()).Import(file.Value);
                });
            });

            app.Command("decrypt", decryptFile =>
            {
                decryptFile.Description = "Decrypts a password file.";
                var passPhrase = decryptFile.Argument("pass phrase", "Pass phrase").IsRequired();
                decryptFile.OnExecute(() =>
                {
                    new Infrastructure.PasswordManager(new EncryptionProvider()).Decrypt(passPhrase.Value);
                });
            });

            app.Command("password", passwordCmd =>
            {
                passwordCmd.OnExecute(() =>
                {
                    Console.WriteLine("Specify what to do with the password.");
                    passwordCmd.ShowHelp();
                    return 1;
                });

                passwordCmd.Command("get", getCmd =>
                {
                    getCmd.Description = "Get a password";
                    var key = getCmd.Argument("key", "Password key.").IsRequired();
                    var passPhrase = getCmd.Argument("pass phrase", "Pass phrase").IsRequired();
                    getCmd.OnExecute(() =>
                    {
                        new Infrastructure.PasswordManager(new EncryptionProvider()).GetPassword(key.Value, passPhrase.Value);
                    });
                });

                passwordCmd.Command("list", listCmd =>
                {
                    var json = listCmd.Option("--json", "Json output", CommandOptionType.NoValue);
                    listCmd.OnExecute(() =>
                    {
                        if (json.HasValue())
                        {
                            Console.WriteLine("{\"dummy\": \"value\"}");
                        }
                        else
                        {
                            Console.WriteLine("dummy = value");
                        }
                    });
                });
            });


            app.OnExecute(() =>
            {
                Console.WriteLine("Specify a subcommand");
                app.ShowHelp();
                return 1;
            });

            return app.Execute(args);
            
        }


        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    var env = hostingContext.HostingEnvironment;
                    config.SetBasePath(env.ContentRootPath);
                })
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHostedService<PasswordManagerService>();
                });
    }
}
