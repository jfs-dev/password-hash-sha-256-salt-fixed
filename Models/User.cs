namespace password_hash_sha_256_salt_fixed.Models;

public class User
{
    public string UserName { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;
}