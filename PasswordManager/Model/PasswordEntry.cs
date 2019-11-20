using System;
using System.Collections.Generic;
using System.Text;

namespace PasswordManager.Model
{
    public class PasswordEntry
    {
        public int Id { get; set; }
        public string Asset { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
