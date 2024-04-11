#include <stdio.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>

int login(char *user, char *passwd)
{
    struct spwd *pw;
    char *epasswd;

    pw = getspnam(user);
    if (pw == NULL)
    {
        printf("User not found\n");
        return 0;
    }
    printf("Login name: %s\n", pw->sp_namp);
    printf("Passwd    : %s\n", pw->sp_pwdp);
    epasswd = crypt(passwd, pw->sp_pwdp);
    if (strcmp(epasswd, pw->sp_pwdp) == 0)
    {
        return 1;
    }
    return 0;
}

void main(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("Please provide a user name and a password\n");
        return;
    }
    int r = login(argv[1], argv[2]);
    printf("Result: %d\n", r);
}