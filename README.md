# Password Manager

My ***inconvinent*** little password manager that I carry around in a USB. I got sick of all the online password managers cause all they did is store my passwords. They did not provide any convinient to change passwords regularly. 

This uses PGP encryption to save a simple csv file (sample attached). You generate your keys, you generate encrypt your password and like any other password mamanger, you remember a passphrase to get your password. 

Download the repo and build it

    dotnet publish PasswordManager.csproj -c Release -o C:\PasswordManager

Now copy your passwords file (like the sample csv) and paste it to C:\PasswordManager (or whereever you published the package).

Now generate your keys

    pm keygen <keyfile> <identit> <passphrase>

Import the passwords file 

    pm import passwords.csv

Get all the password mathing a key 

    pm password get yahoo <passphrase>

Inconvinient, but it all stays with you. 
