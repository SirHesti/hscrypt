#ifndef HSCRYPT_H
#define HSCRYPT_H

// redfine crypt_xtrn overwrite if exists
#ifdef crypt_xtrn
  #undef crypt_xtrn
#endif //crypt_xtrn

// if not main so is it extern
#ifdef HSCRYPT_C_MAIN
  #define crypt_xtrn
#else
  #define crypt_xtrn extern
#endif //HSCRYPT_C_MAIN

#ifdef  __cplusplus
extern "C" {
#endif

// Funktionen
//______________________________________________________________________________

void HScryptInit(void);

signed int LoadGClock (char *Filename);
signed int SaveGClock (char *Filename);

void zfa_Randomize(void);
void zfa_Dump(void);
int zfa_Check(void);
void BuildReZFA(void);

signed int CryptFile(void);
int CryptChar(int inchar);

signed int xDecryptFile(void);
int DeCryptChar(int inchar);
int isPWasc(int c);

// Variablen
//______________________________________________________________________________

crypt_xtrn char Input_Filename[PATH_MAX];
crypt_xtrn char Output_Filename[PATH_MAX];

crypt_xtrn int pwc;    // count
crypt_xtrn int pwl;    // length
crypt_xtrn char password[256];

#define ZFA_MAX 256
crypt_xtrn int de_zfa[ZFA_MAX];
crypt_xtrn int OverwriteTarget;
crypt_xtrn int password_only_mode;

// For Copy normal 4096
//#define BUFF_LEN 128
#define BUFF_LEN 4096
crypt_xtrn unsigned char buffer[BUFF_LEN];

typedef struct t_HSCrypt_KeyFile{
    char    Ident[16];
    time_t  create_time;
    int     vers;
    unsigned char zfa_field[256];
}t_HSCrypt_KeyFile;
crypt_xtrn t_HSCrypt_KeyFile HSCrypt_KeyFile;

typedef struct t_HSCrypt_Header{
    char    Ident[16];
    time_t  create_time;
    int     vers;
}t_HSCrypt_Header;
crypt_xtrn t_HSCrypt_Header HSCrypt_Header;

crypt_xtrn char *HSCrypt_KeyFile_Name;
crypt_xtrn char *HSCrypt_Header_Name;
crypt_xtrn int zfa[ZFA_MAX];

#ifdef  __cplusplus
}
#endif // __cplusplus
#endif // HSCRYPT_H
