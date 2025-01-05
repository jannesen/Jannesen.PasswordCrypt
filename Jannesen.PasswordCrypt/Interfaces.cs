using System;

namespace Jannesen.PasswordCrypt
{
    public interface IPasswordHash
    {
        string      StartWith                   { get; }
        string      Create(string password);
        bool        Verify(string password, string passwordHash);
    }
}