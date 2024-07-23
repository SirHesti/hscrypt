#include "tools.h"
#include "VERSION.h"
#include "hscrypt.h"

int WisperMode=0;

signed int main(int argc, char *argv[])
{
    int GClock_LoadOrSave;
    int DecryptMode;

    if (InitTools(argc , argv, "%v%t%d%m", I_MAJOR, I_MINOR, I_BUILD, I_BETA, LOG_STDERR)) return -1;
    if ( ( ChkARG("-?", argc,argv) ) || (argc<2) )
    {
        printf ("%s OPTIONS:\n",m_PRGNAME);
        printf ("   -p <password> quiz what is this (optional)\n");
        printf ("   -d decrypt mode\n");
        printf ("\n");
        printf ("   -b buildin DATA\n");
        printf ("   -r randomize GLock DATA\n");
        printf ("   -l <Filename> Glock Data load\n");
        printf ("   -s <Filename> Glock Data save\n");
        printf ("\n");
        printf ("   -i <Filename> Read this file\n");
        printf ("   -o <Filename> write this file\n");
        printf ("   -t Overwrite target\n");
        printf ("if  Output<Filename> is missing so we try to get it from -i option\n");
        printf ("\n");
        printf ("   -z Dump randomblock end exit\n");
        printf ("   -w wispher mode (only error displayed)\n");
        printf ("\n");
        return 0;
    }
    HScryptInit();
//    printf ("BEFORE_DUMP\n"); zfa_Dump(); return 255;

    DecryptMode=0;
    GClock_LoadOrSave=0;
    InitARG(argc);
    if (ChkARG("-w",argc,argv)) WisperMode=1;
    else printf("%s\n", m_PRG_INFO);
    if (ChkARG("-i",argc,argv))
    {
        if (!ARG)
        {
            lprintf ("-i without InputFile");
            return 2;
        }
        strcpy (Input_Filename,ARG);
    }

    if (ChkARG("-o",argc,argv))
    {
        if (!ARG)
        {
            lprintf ("-o without OutFile");
            return 2;
        }
        strcpy (Output_Filename,ARG);
    }

    if (ChkARG("-r",argc,argv))
    {
        zfa_Randomize();
        GClock_LoadOrSave |= 0x100;
    }
    if (ChkARG("-b",argc,argv))
    {
        GClock_LoadOrSave |= 0x002;
    }
    if (ChkARG("-l",argc,argv))
    {
        if (GClock_LoadOrSave) lprintf ("warning GClock random & load used");
        if (LoadGClock (ARG)) return 0x10;
        GClock_LoadOrSave |= 0x001;
    }
    if (ChkARG("-s",argc,argv))
    {
        if (SaveGClock (ARG))
        {
            lprintf ("ERROR: GClock save failed");
            return 0x11;
        }
        GClock_LoadOrSave |= 0x010;
    }else{
        if (GClock_LoadOrSave & 0x100)
        {
            lprintf ("ERROR: GClock random & save NOT used; abort");
            return 1;
        }
    }
    if (GClock_LoadOrSave==0) password_only_mode = 1;
    BuildReZFA();

    if (ChkARG("-p",argc,argv))
    {
        if (!ARG)
        {
            lprintf ("-p given without your ARG");
            return 4;
        }
        for (pwl=0;;pwl++)
        {
            if (ARG[pwl]==0)
            {
                password[pwl]=0;
                break;
            }
            if (!isPWasc(ARG[pwl])) return 4;
            password[pwl]=ARG[pwl]; // -' '
        }
    }

    if (ChkARG("-z",argc,argv))
    {
        zfa_Dump();
        return 0;
    }

    if (ChkARG("-d",argc,argv)) DecryptMode=1;
    if (ChkARG("-t",argc,argv)) OverwriteTarget=1;

    if (arg_unused_print(argc,argv)) return 1;
    arg_Clean ();
    if (zfa_Check())
    {
        lprintf ("ERROR: zfa missmatch; abort");
        return 0x11;
    }
    if (DecryptMode) return xDecryptFile();
    return CryptFile();
}
