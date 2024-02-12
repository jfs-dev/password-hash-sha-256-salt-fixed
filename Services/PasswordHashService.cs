using System.Security.Cryptography;
using System.Text;

namespace password_hash_sha_256_salt_fixed.Services;

public class PasswordService
{
    private const string Salt = "MeuSaltFixoSuperSecreto";

    public static string CreatePasswordHash(string password)
    {
        byte[] saltBytes = Encoding.UTF8.GetBytes(Salt);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        
        byte[] hashBytes = CalculateHash(passwordBytes, saltBytes);

        return Convert.ToBase64String(hashBytes);
    }

    public static bool VerifyPassword(string password, string hashedPassword)
    {
        byte[] hashWithSalt = Convert.FromBase64String(hashedPassword);
        
        byte[] saltBytes = Encoding.UTF8.GetBytes(Salt);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        byte[] computedHash = CalculateHash(passwordBytes, saltBytes);

        return CompareByteArrays(hashWithSalt, computedHash);
    }

    private static byte[] CalculateHash(byte[] passwordBytes, byte[] saltBytes)
    {
        byte[] combinedBytes = CombineByteArrays(passwordBytes, saltBytes);
        
        return SHA256.HashData(combinedBytes);
    }

    private static bool CompareByteArrays(byte[] array1, byte[] array2)
    {
        if (array1.Length != array2.Length) return false;

        for (int i = 0; i < array1.Length; i++)
            if (array1[i] != array2[i]) return false;

        return true;
    }

    private static byte[] CombineByteArrays(byte[] array1, byte[] array2)
    {
        byte[] combined = new byte[array1.Length + array2.Length];
        
        Array.Copy(array1, 0, combined, 0, array1.Length);
        Array.Copy(array2, 0, combined, array1.Length, array2.Length);
        
        return combined;
    }
}