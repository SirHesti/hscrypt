/*
**  Crypt - Files !
**
**  HS  Heiko Stoevesandt
**
** Created '10.2017  Console - Version
** V1.0    10.2017 HS Created
** 02.06.24 HS password_only
** 13.06.24 HS Fehler im zfa_init gefunden m) :(
** 23.07.24 HS Schreib- und Lesevorgänge prüfen und ggf. mit errorlevel beenden
** 23.07.24 HS nur mit gültigen ZFA wird gestartet
**_____________________________________________________________________________
**
** ReturnCodes
**
**      0   OK
**     -1   Init Failure
**      1   Global Failure
**      2   Input File failure
**      3   Output File failure
**      4   password error
**   0x10   Load failure
**_____________________________________________________________________________
**
** SOME parameter for testing
**_____________________________________________________________________________
**
** -i history.txt -o C:\HS\tmp\output.cip  -t
** -l C:\HS\etc\crypt_null.key
**
** -i C:\HS\tmp\indo.txt -o C:\HS\tmp\output.cip  -t -p Hesti
** -o C:\HS\tmp\indo_rev.txt -i C:\HS\tmp\output.cip  -t -p Hesti -d

 /hs/src/gui/hscrypt/hscrypt -s /hs/tmp/hsc.key   *** fehlermeldung ignorieren
 /hs/src/gui/hscrypt/hscrypt -i /hs/tmp/backup1.tgz -t -o /hs/tmp/x.txt.hsc -l /hs/tmp/hsc.key -p hs
 /hs/src/gui/hscrypt/hscrypt -o /hs/tmp/backup2.tgz -t -i /hs/tmp/x.txt.hsc -l /hs/tmp/hsc.key -p hs -d

*/

#include "tools.h"
#include "VERSION.h"

#define HSCRYPT_C_MAIN
#include "hscrypt.h"
#undef  HSCRYPT_C_MAIN

// Thats was only random generated Data, nothing else
int zfa_init[ZFA_MAX]={
214,209,172,166, 67, 63,130,  5,198, 19, 43,220, 15, 16,237,167,
184, 53, 94,248, 29, 64,212, 25,110,111, 30,243,  3,141,112, 46,
239, 45,164,154,215, 49,160,206,  6,143, 20, 17,185, 85,101,115,
190,234,238, 69, 70,150,100,173,240, 68,153,136, 36,135,103,157,
174,221,228,244,125, 47,222,124,210,161,126,249,127,134, 84, 22,
128,180,121,223,211,252,  7, 72,146,242,205, 56, 54,245, 74,137,
 55,102,216,122,224, 65, 31, 89, 86,204,213, 96,  4,175,165,217,
 28, 32,106,131,113,123,162, 57,129,  0, 33,202,225,218,  1, 58,
181, 80,226,246,158,108, 78,171,182,159,132, 18,250,120, 60,  8,
196,176, 40,  9,191, 23, 34,192,227,247,251, 10,199, 61,116,241,
 79, 38,109, 44,104,187, 87,188, 35,155,229,207,255,253, 11,230,
156,235, 27, 37,114,219,105, 41,231, 93,194,186,151, 48,138,254,
 50,117,232,233,236, 59, 24,  2,183, 77,107, 98,193, 51, 12,177,
208, 95,178,179, 39, 13, 99,189,152,195, 14,163, 21,197, 52,168,
133,200,169, 26,201, 42,139, 62,170, 66,140,149, 71,142,203, 73,
144,145, 75,118,147, 76, 81, 82, 83, 88, 90,148, 91, 92, 97,119
};

void HScryptInit(void)
{
    int i;
    pwc                 =0;
    OverwriteTarget     =0;
    Input_Filename[0]   =0;
    Output_Filename[0]  =0;
    ZeroMemory(password, sizeof(password));
    password_only_mode  =0;

    HSCrypt_KeyFile_Name="HSCrypt KeyFile";
    HSCrypt_Header_Name="HSCrypt Header ";

    ZeroMemory(de_zfa,ZFA_MAX);
    ZeroMemory(zfa,ZFA_MAX);

    for (i=0;i<ZFA_MAX;i++)
    {
        zfa[i]=zfa_init[i];
    }
}

// 29.10.2017 HS Checkallowd chars in PW
//_____________________________________________________________________________

int isPWasc(int c)
{
  return ((c >' ' && c <= '~') ? 1 : 0);
}

// 29.10.2017 HS Reverse Datablock build
//_____________________________________________________________________________

void BuildReZFA(void)
{
    int i;
    for (i=0;i<ZFA_MAX;i++)
    {
        de_zfa[zfa[i]]=i;
    }
}

// 28.10.2017 HS Save Datablock 2 File
//_____________________________________________________________________________

signed int SaveGClock (char *Filename)
{
    int i;
    FILE *F;
    if (FileOK(Filename))                                                       // Check  if present
    {
        lprintf ("never overwrite exists Keyfile: %s", Filename);
        return -1;                                                              // Abort if exists
    }
    strcpy (HSCrypt_KeyFile.Ident, HSCrypt_KeyFile_Name);                       // Create struct
    HSCrypt_KeyFile.create_time = unixtime();
    HSCrypt_KeyFile.vers = I_MAJOR;
    for (i=0;i<ZFA_MAX;i++)
    {
        HSCrypt_KeyFile.zfa_field[i] = zfa[i];
    }
    if ((F=fopen(Filename,"wb"))==NULL)                                         // Write File
    {
        lprintf ("ERROR: File can't write : %s", Filename);
        return -2;
    }
    fwrite (&HSCrypt_KeyFile, 1, sizeof(HSCrypt_KeyFile),F);
    fclose (F);
    return 0;
}


// 28.10.2017 HS Load Datablock from File
//_____________________________________________________________________________

signed int LoadGClock (char *Filename)
{
    int i;
    size_t s;
    FILE *F;

    if (!FileOK(Filename)) return -1;                                           // Check for exists
    if ((F=fopen(Filename,"rb"))==NULL)
    {
        lprintf ("ERROR: read : %s", Filename);
        return -2;
    }
    s = fread (&HSCrypt_KeyFile, 1, sizeof(HSCrypt_KeyFile),F);                 // Read bytes from Files
    fclose (F);
    if (s!=sizeof(HSCrypt_KeyFile))                                             // Suze must be the same
    {
        lprintf ("File load, but size wrong %i %i", s, sizeof(HSCrypt_KeyFile));
        return -3;
    }
    if (strcmp(HSCrypt_KeyFile.Ident, HSCrypt_KeyFile_Name))                    // Ident must ve the Same
    {
        lprintf ("File load, but wrong header");
        return -4;
    }
    if ( (HSCrypt_KeyFile.vers < 1) || (HSCrypt_KeyFile.vers > I_MAJOR) )       // HSCrypt_KeyFile.vers checked now
    {
        lprintf ("File load, but wrong version");
        return -5;
    }
    for (i=0;i<ZFA_MAX;i++)
    {
        zfa[i] = HSCrypt_KeyFile.zfa_field[i];
    }
    return 0;
}

// 28.10.2017 HS New Datafield creation
//_____________________________________________________________________________

void zfa_Randomize(void)
{
    // * Randomize Field *
    int i,k;
    int r;
    srand (time(NULL));

    // * delete Field *
    for (i=0;i<ZFA_MAX;i++)
    {
        zfa[i]=-1;
        //zfa[i]=i;
    }
    //return;

    // * fill field
    // best loop 0 to 511 (k!) whorse loop 0 to 65535
    for (i=0;i<ZFA_MAX;i++)
    {
        // Get random number
        r = rand () % ZFA_MAX;

        // Make it unique
        for (k=0;;k++)
        {
            if (k>=ZFA_MAX) break;  // found ? while k > zfa_max
            if (zfa[k]==r)          // found in table ?
            {
                r++;                // increase
                r = r % ZFA_MAX;    // make it to the max
                k=0;                // restart in field search
                continue;           // restart !!
            }
        }
        zfa[i]=r;
        // printf ("%i\n",r);
    }
}

// testing if any field an unique
int zfa_Check(void)
{
    int i,j,f,c,rc;
    int field[256];
    ZeroMemory(field,_countof(field));
    rc = 0;

    for     (i=0;i<_countof(field);i++)
    {
        field[zfa[i]]=1;
    }
    for     (i=0;i<_countof(field);i++)
    {
        if (field[i]==0)
        {
            lprintf ("empty field=%i",i);
            rc++;
        }
    }

    for (i=0;i<(_countof(field)-1);i++)
    {
        f = zfa[i];
        for (j=i+1;j<_countof(field);j++)
        {
            c = zfa[j];
            if (f!=c) continue;
            lprintf ("dupe %i : %i   -> %i %i",i,j,f,c);
            rc++;
        }
    }
    return rc;
}

//
// this was wrote for code testing
//_______________________________________

void zfa_Dump(void)
{
    int i,j;
    zfa_Check();


    printf ("ZFA\n");
    for (i=0;i<ZFA_MAX;i+=16)
    {
        printf ("%02x:",i);
        for (j=0;j<16;j++)
        {
            if (j!=0) printf (" ");
            printf ("%3i",zfa[i+j]);
        }
        printf (" - ");
        for (j=0;j<16;j++)
        {
            if (j!=0) printf (" ");
            printf ("%02x",zfa[i+j]);
        }
//        for (j=0;j<16;j++)
//        {
//            if (isprint(zfa[i+j])) printf("%c",zfa[i+j]);
//            else printf ("%c",zfa[i+j]);
//        }
        printf ("\n");
    }
    printf ("DE_ZFA\n");
    for (i=0;i<ZFA_MAX;i+=16)
    {
        printf ("%02x:",i);
        for (j=0;j<16;j++)
        {
            if (j!=0) printf (" ");
            printf ("%3i",de_zfa[i+j]);
        }
        printf (" - ");
        for (j=0;j<16;j++)
        {
            if (j!=0) printf (" ");
            printf ("%02x",de_zfa[i+j]);
        }
        printf ("\n");
    }
}

// 29.10.2017 HS Cryptfile
//_____________________________________________________________________________

signed int CryptFile(void)
{
    FILE *I;
    FILE *O;
    size_t BufLen;
    size_t WrtLen;
    int i;

    if (Output_Filename[0]==0)
    {
        lprintf ("OutputFilename not given abort;");
        return 3;
    }
    if (FileOK(Output_Filename))
    {
        if (OverwriteTarget==0)
        {
            lprintf ("OutputFile (%s) exists not overwritten !!", Output_Filename);
            return 3;
        }
    }
    if ((I=fopen(Input_Filename,"rb"))==NULL)
    {
        lprintf ("ERROR: read : %s", Input_Filename);
        return 2;
    }
    if ((O=fopen(Output_Filename,"wb"))==NULL)
    {
        lprintf ("ERROR: open Ouput : %s", Output_Filename);
        fclose (I);
        return 3;
    }
    strcpy (HSCrypt_Header.Ident, HSCrypt_Header_Name);                        // Create struct
    HSCrypt_Header.create_time = unixtime();
    HSCrypt_Header.vers = ( I_MAJOR*0x1000000) + (I_MINOR*0x10000) + I_BUILD;
    WrtLen = fwrite (&HSCrypt_Header, 1, sizeof(HSCrypt_Header),O);
    if ( WrtLen != sizeof(HSCrypt_Header) )
    {
        lprintf ("ERROR: open Ouput Header: %s", Output_Filename);
        fclose (O);
        fclose (I);
        return 3;
    }

#ifdef xHS_DEBUG
    char *a = (char*) &HSCrypt_Header;
    for (i=0;i<sizeof(HSCrypt_Header);i++)
    {
        printf (" %02x", (unsigned int) a[i]);
    }
    printf ("\n");
#endif
    for(;;)
    {
        BufLen = fread(buffer, 1, BUFF_LEN, I);
        if (BufLen==0) break;
        // Create crypted Block
        for (i=0;i<BufLen;i++)
        {
            buffer[i]=CryptChar(buffer[i]);
        }
        WrtLen = fwrite(buffer, 1, BufLen, O);
        if (WrtLen != BufLen)
        {
            lprintf ("ERROR:write Ouput: %s", Output_Filename);
            fclose (O);
            fclose (I);
            return 3;
        }
    }
    fclose (I);
    fclose (O);
    return 0;
}

signed int xDecryptFile(void)
{
    FILE *I;
    FILE *O;
    size_t BufLen;
    size_t WrtLen;
    size_t s;

    int i;

    if (Output_Filename[0]==0)
    {
        lprintf ("OutputFilename not given abort;");
        return 3;
    }
    if (FileOK(Output_Filename))
    {
        if (OverwriteTarget==0)
        {
            lprintf ("OutputFile (%s) exists not overwritten !!", Output_Filename);
            return 3;
        }
    }
    if ((I=fopen(Input_Filename,"rb"))==NULL)
    {
        lprintf ("ERROR: read : %s", Input_Filename);
        return 2;
    }
    s = fread (&HSCrypt_Header, 1, sizeof(HSCrypt_Header),I);                   // Read bytes from Files
    if (s!=sizeof(HSCrypt_Header))                                              // Size must be fit
    {
        lprintf ("File load, but size wrong %i %i", s, sizeof(HSCrypt_Header));
        fclose (I);
        return 2;
    }
    if (strcmp(HSCrypt_Header.Ident, HSCrypt_Header_Name))                      // Ident must be the Same
    {
        lprintf ("File with wrong header");
        fclose (I);
        return 2;
    }
    if ( (HSCrypt_Header.vers < 1) || ((HSCrypt_Header.vers/0x1000000) > I_MAJOR) )         // HSCrypt_Header.vers checked now
    {
        lprintf ("Fileheader wrong version");
        fclose (I);
        return 2;
    }

    if ((O=fopen(Output_Filename,"wb"))==NULL)
    {
        lprintf ("ERROR: open Ouput : %s", Output_Filename);
        fclose (I);
        return 2;
    }
    for(;;)
    {
        BufLen=fread(buffer, 1, BUFF_LEN, I);
        if (BufLen==0) break;
        // Create decrypted Block
        for (i=0;i<BufLen;i++)
        {
            buffer[i]=DeCryptChar(buffer[i]);
        }
        WrtLen = fwrite(buffer, 1, BufLen, O);
        if (WrtLen != BufLen)
        {
            lprintf ("ERROR:write Ouput: %s", Output_Filename);
            fclose (O);
            fclose (I);
            return 2;
        }
    }
    fclose (I);
    fclose (O);
    return 0;
}
int CryptChar(int inchar)
{
    int c;
    if (password_only_mode) c=inchar+16;
    else c = zfa[inchar];               // got from Keyfile
    if (pwl)
    {
        c = c + password[pwc];              // crypting like Vigenére
        pwc++;                              // to next char
        if (pwc>=pwl) pwc=0;                // overflow
    }
    c = c % 256;                        // got in range
    return c;
}

int DeCryptChar(int inchar)
{
    int c;
    if (password_only_mode) c = (inchar - 16);
    else c = inchar; // decrypting like Vigenére
    c = c + 256;
    if (pwl)
    {
        c = c-password[pwc];
        pwc++;                              // to next char
        if (pwc>=pwl) pwc=0;                // overflow
    }
    c = c % 256;
    if (!password_only_mode) c = de_zfa[c]; // got in range from Keyfile
    return c;
}
