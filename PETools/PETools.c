// filename: PETools.c
// author  : Tim Bateman
// date    : 2012/05/01
// summary : simple command line app to output PE file information
#include "targetver.h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <tchar.h>
#include <windows.h>

typedef struct
{
    BOOL        bDumpExports;
    BOOL        bDumpImports;
    TCHAR       pszFileName[ MAX_PATH ];
} CmdArgs, *PCmdArgs;

/******************* GLOBALS *******************/
PIMAGE_DOS_HEADER       g_pDosHdr   = NULL;
PIMAGE_NT_HEADERS32     g_pNT32Hdr  = NULL;
PIMAGE_NT_HEADERS64     g_pNT64Hdr  = NULL;
BOOL                    g_bIs64Bit  = FALSE;


void usage( _TCHAR* pszName )
{
    _tprintf( _T("%s [--exports] [--imports] <filename>\n"), pszName );
}

BOOL parseArgs( int argc, _TCHAR* argv[], PCmdArgs pArgs )
{
    BOOL        bRetVal     = FALSE;
    int         dwCurrent   = 0;
    if( pArgs )
    {
        bRetVal = TRUE;
        for( dwCurrent = 1 ; dwCurrent < argc ; dwCurrent++ )
        {
            if(        0 == _tcscmp( _T("--imports"), argv[ dwCurrent ] ) )
            {
                pArgs->bDumpImports = TRUE;
            } else if( 0 == _tcscmp( _T("--exports"), argv[ dwCurrent ] ) )
            {
                pArgs->bDumpExports = TRUE;
            } else {
                // must be the file name
                _tcsncat( pArgs->pszFileName, argv[ dwCurrent ], MAX_PATH );
                // make sure its NULL terminated
                pArgs->pszFileName[ MAX_PATH - 1 ] = _T('\0');
            }
        }

        // check we got  a filename
        if( 0 == _tcscmp( _T(""), pArgs->pszFileName ) )
        {
            bRetVal = FALSE;
        }
    }
    return bRetVal;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader32(DWORD rva, PIMAGE_NT_HEADERS32 pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;

    for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        // is the RVA within this section?
        if ( (rva >= section->VirtualAddress) &&
             (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return section;
    }

    return NULL;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader64(DWORD rva, PIMAGE_NT_HEADERS64 pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;

    for ( i=0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        // is the RVA within this section?
        if ( (rva >= section->VirtualAddress) &&
             (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return section;
    }

    return NULL;
}

LPVOID GetPtrFromRVA32( DWORD rva, PIMAGE_NT_HEADERS32 pNTHeader, DWORD imageBase )
{
        PIMAGE_SECTION_HEADER   pSectionHdr = NULL;
        INT                     delta       = 0;

        pSectionHdr = GetEnclosingSectionHeader32( rva, pNTHeader );
        if ( NULL == pSectionHdr )
                return 0;

        delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
        return (PVOID) ( imageBase + rva - delta );
}

LPVOID GetPtrFromRVA64( DWORD rva, PIMAGE_NT_HEADERS64 pNTHeader, DWORD imageBase )
{
        PIMAGE_SECTION_HEADER   pSectionHdr = NULL;
        INT                     delta       = 0;

        pSectionHdr = GetEnclosingSectionHeader32( rva, pNTHeader );
        if ( NULL == pSectionHdr )
                return 0;

        delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
        return (PVOID) ( imageBase + rva - delta );
}

BOOL validate( PBYTE pBuffer, DWORD dwBufferSize )
{
    BOOL                    bRetVal = FALSE;

    bRetVal = ( pBuffer && dwBufferSize > sizeof( IMAGE_DOS_HEADER ) );

    if( bRetVal )
    {
        g_pDosHdr = (PIMAGE_DOS_HEADER) pBuffer;
    }

    bRetVal = bRetVal && ( IMAGE_DOS_SIGNATURE == g_pDosHdr->e_magic );

    if( bRetVal )
    {
        g_pNT32Hdr = (PIMAGE_NT_HEADERS32)( pBuffer + g_pDosHdr->e_lfanew );
        g_pNT64Hdr = (PIMAGE_NT_HEADERS64)( pBuffer + g_pDosHdr->e_lfanew );
    }

    bRetVal = bRetVal && ( ( ((PBYTE)(g_pNT32Hdr + 1)) - pBuffer )  < dwBufferSize );

    // same on 32 and 64 bit
    bRetVal = bRetVal && ( IMAGE_NT_SIGNATURE == g_pNT32Hdr->Signature );


    // same on FileHeader stuctrure is the same on both 32 and 64bit
    bRetVal = bRetVal && ( ( IMAGE_FILE_MACHINE_I386  == g_pNT32Hdr->FileHeader.Machine                                  ) ||
                           ( IMAGE_FILE_MACHINE_AMD64 == g_pNT32Hdr->FileHeader.Machine && TRUE == ( g_bIs64Bit = TRUE ) )    );

    return bRetVal;
}

VOID printSummary( PBYTE pBuf, DWORD dwBufSize )
{
    DWORD                   dwCurSectionHdr = 0;
    PIMAGE_SECTION_HEADER   pSectionHdr     = NULL;

    _tprintf( _T("Machine         : %s\n"), ( g_bIs64Bit ) ? _T("IMAGE_FILE_MACHINE_AMD64") : _T("IMAGE_FILE_MACHINE_I386") );

    _tprintf( _T("Sections        : %d\n"), g_pNT32Hdr->FileHeader.NumberOfSections );

    _tprintf( _T("Characteristics : ") );
    if( IMAGE_FILE_RELOCS_STRIPPED  & g_pNT32Hdr->FileHeader.Characteristics )
        _tprintf( _T("IMAGE_FILE_RELOCS_STRIPPED ") );
    if( IMAGE_FILE_EXECUTABLE_IMAGE & g_pNT32Hdr->FileHeader.Characteristics )
        _tprintf( _T("IMAGE_FILE_EXECUTABLE_IMAGE ") );
    if( IMAGE_FILE_32BIT_MACHINE    & g_pNT32Hdr->FileHeader.Characteristics )
        _tprintf( _T("IMAGE_FILE_32BIT_MACHINE ") );
    if( IMAGE_FILE_DEBUG_STRIPPED   & g_pNT32Hdr->FileHeader.Characteristics )
        _tprintf( _T("IMAGE_FILE_DEBUG_STRIPPED ") );
    if( IMAGE_FILE_SYSTEM           & g_pNT32Hdr->FileHeader.Characteristics )
       _tprintf( _T("IMAGE_FILE_SYSTEM ") );
    if( IMAGE_FILE_DLL              & g_pNT32Hdr->FileHeader.Characteristics )
        _tprintf( _T("IMAGE_FILE_DLL ") );
    _tprintf( _T("\n") );

    if( g_bIs64Bit )
    {
        _tprintf( _T("Linker Version  : %d.%d\n"), g_pNT64Hdr->OptionalHeader.MajorLinkerVersion, g_pNT64Hdr->OptionalHeader.MinorLinkerVersion );

        _tprintf( _T("Entry Point     : %016lx\n"), g_pNT64Hdr->OptionalHeader.AddressOfEntryPoint );

        _tprintf( _T("Image Base      : %016lx\n"), g_pNT64Hdr->OptionalHeader.ImageBase );

        _tprintf( _T("DLL Character.  : ") );
        if( IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE           & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ") );
        if( IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY        & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ") );
        if( IMAGE_DLLCHARACTERISTICS_NX_COMPAT              & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NX_COMPAT ") );
        if( IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ") );
        if( IMAGE_DLLCHARACTERISTICS_NO_SEH                 & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NO_SEH ") );
        if( IMAGE_DLLCHARACTERISTICS_NO_BIND                & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NO_BIND ") );
        if( IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ") );
        if( IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  & g_pNT64Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ") );
        _tprintf( _T("\n") );


    } else {

        _tprintf( _T("Linker Version  : %d.%d\n"), g_pNT32Hdr->OptionalHeader.MajorLinkerVersion, g_pNT32Hdr->OptionalHeader.MinorLinkerVersion );

        _tprintf( _T("Entry Point     : %08lx\n"), g_pNT32Hdr->OptionalHeader.AddressOfEntryPoint );

        _tprintf( _T("Image Base      : %08lx\n"), g_pNT32Hdr->OptionalHeader.ImageBase );

        _tprintf( _T("DLL Character.  : ") );
        if( IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE           & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ") );
        if( IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY        & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ") );
        if( IMAGE_DLLCHARACTERISTICS_NX_COMPAT              & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NX_COMPAT ") );
        if( IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ") );
        if( IMAGE_DLLCHARACTERISTICS_NO_SEH                 & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NO_SEH ") );
        if( IMAGE_DLLCHARACTERISTICS_NO_BIND                & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_NO_BIND ") );
        if( IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ") );
        if( IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  & g_pNT32Hdr->OptionalHeader.DllCharacteristics )
            _tprintf( _T("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ") );
        _tprintf( _T("\n") );
    }
    pSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)&( g_pNT32Hdr->OptionalHeader )) + g_pNT32Hdr->FileHeader.SizeOfOptionalHeader);
    for( dwCurSectionHdr = 0 ; dwCurSectionHdr < g_pNT32Hdr->FileHeader.NumberOfSections ; dwCurSectionHdr++ )
    {
        _tprintf(
#ifdef _UNICODE
            _T("Section         : %S\n"),
#else
            _T("Section         : %s\n"),
#endif
            pSectionHdr[ dwCurSectionHdr ].Name );
    }


}
VOID printImports( PBYTE pBuf, DWORD dwBufSize )
{
    PIMAGE_IMPORT_DESCRIPTOR    pImportDesc = NULL;
    PIMAGE_THUNK_DATA32         pThunk32    = NULL,
                                pIATThunk32 = NULL;
    PIMAGE_THUNK_DATA64         pThunk64    = NULL,
                                pIATThunk64 = NULL;
    PIMAGE_IMPORT_BY_NAME       pOrdinalName= NULL;

    if( g_bIs64Bit )
    {
        if( g_pNT64Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size           &&
            g_pNT64Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress    )
        {
            pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) GetPtrFromRVA64(
                           g_pNT64Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress,
                           g_pNT64Hdr, pBuf );

            _tprintf( _T("Imports         :\n") );
            while( pImportDesc->Name )
            {
                char *pName = (char*) GetPtrFromRVA64( pImportDesc->Name, g_pNT64Hdr, pBuf );

                _tprintf(
#ifdef _UNICODE
                    _T("\t%S\n"),
#else
                    _T("\t%s\n"),
#endif
                    pName );

                pThunk64    = (PIMAGE_THUNK_DATA32) GetPtrFromRVA64( pImportDesc->Characteristics, g_pNT64Hdr, pBuf );
                pIATThunk64 = (PIMAGE_THUNK_DATA32) GetPtrFromRVA64( pImportDesc->FirstThunk,      g_pNT64Hdr, pBuf );

                while( 1 )
                {
                    if( 0 == pThunk64->u1.AddressOfData )
                    {
                        // done here
                        break;
                    } else {
                        if ( pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG )
                        {
                            _tprintf( _T("\t\t%4u\n"), IMAGE_ORDINAL(pThunk64->u1.Ordinal) );
                        } else {
                            pOrdinalName = (PIMAGE_IMPORT_BY_NAME) pThunk64->u1.AddressOfData;
                            pOrdinalName = (PIMAGE_IMPORT_BY_NAME)
                                             GetPtrFromRVA64((DWORD)pOrdinalName, g_pNT64Hdr, pBuf);

                            _tprintf(
#ifdef _UNICODE
                                _T("\t\t%4u  %S\n"),
#else
                                _T("\t\t%4u  %s\n"),
#endif
                                pOrdinalName->Hint, pOrdinalName->Name );
                        }
                    }

                    pThunk64++;
                    pIATThunk64++;
                }

                pImportDesc++;
            }
        } else {
            _tprintf( _T("Imports         : none.\n") );
        }
    } else {
        if( g_pNT32Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size           &&
            g_pNT32Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress    )
        {
            pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) GetPtrFromRVA32(
                           g_pNT32Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress,
                           g_pNT32Hdr, pBuf );

            _tprintf( _T("Imports         :\n") );
            while( pImportDesc->Name )
            {
                char *pName = (char*) GetPtrFromRVA32( pImportDesc->Name, g_pNT32Hdr, pBuf );

                _tprintf(
#ifdef _UNICODE
                    _T("\t%S\n"),
#else
                    _T("\t%s\n"),
#endif
                    pName );

                pThunk32    = (PIMAGE_THUNK_DATA32) GetPtrFromRVA32( pImportDesc->Characteristics, g_pNT32Hdr, pBuf );
                pIATThunk32 = (PIMAGE_THUNK_DATA32) GetPtrFromRVA32( pImportDesc->FirstThunk,      g_pNT32Hdr, pBuf );

                while( 1 )
                {
                    if( 0 == pThunk32->u1.AddressOfData )
                    {
                        // done here
                        break;
                    } else {
                        if ( pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG )
                        {
                            _tprintf( _T("\t\t%4u\n"), IMAGE_ORDINAL(pThunk32->u1.Ordinal) );
                        } else {
                            pOrdinalName = (PIMAGE_IMPORT_BY_NAME) pThunk32->u1.AddressOfData;
                            pOrdinalName = (PIMAGE_IMPORT_BY_NAME)
                                             GetPtrFromRVA32((DWORD)pOrdinalName, g_pNT32Hdr, pBuf);

                            _tprintf(
#ifdef _UNICODE
                                _T("\t\t%4u  %S\n"),
#else
                                _T("\t\t%4u  %s\n"),
#endif
                                pOrdinalName->Hint, pOrdinalName->Name );
                        }
                    }

                    pThunk32++;
                    pIATThunk32++;
                }

                pImportDesc++;
            }
        } else {
            _tprintf( _T("Imports         : none.\n") );
        }
    }
}
VOID printExports( PBYTE pBuf, DWORD dwBufSize )
{
    if( g_bIs64Bit )
    {
        if( g_pNT64Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size           &&
            g_pNT64Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress    )
        {
        } else {
            _tprintf( _T("Exports         : none.\n") );
        }
    } else {
        if( g_pNT32Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size           &&
            g_pNT32Hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress    )
        {
        } else {
            _tprintf( _T("Exports         : none.\n") );
        }
    }
}

int _tmain(int argc, _TCHAR* argv[])
{
    CmdArgs     sArgs       =   { 0 };
    HANDLE      hFile       =   INVALID_HANDLE_VALUE;
    HANDLE      hMap        =   INVALID_HANDLE_VALUE;
    DWORD       dwFileSize  =   0;
    DWORD       dwFileSiseH =   0;
    PBYTE       pFileBuffer =   NULL;

    if( parseArgs( argc, argv, &sArgs ) )
    {
        hFile = CreateFile( sArgs.pszFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL );
        if( INVALID_HANDLE_VALUE != hFile )
        {
            dwFileSize = GetFileSize( hFile, &dwFileSiseH );
            if( dwFileSize && 0 == dwFileSiseH )
            {
                // map into memory
                hMap = CreateFileMapping(   hFile,
                                            NULL,
                                            PAGE_READONLY,
                                            dwFileSiseH, dwFileSize, NULL );
                if( hMap )
                {
                    pFileBuffer = MapViewOfFile( hMap, FILE_MAP_READ, 0, 0, dwFileSize );

                    if( pFileBuffer )
                    {
                        if( validate( pFileBuffer, dwFileSize ) )
                        {

                            printSummary( pFileBuffer, dwFileSize );

                            if( sArgs.bDumpImports )
                                printImports( pFileBuffer, dwFileSize );
                            if( sArgs.bDumpExports )
                                printExports( pFileBuffer, dwFileSize );

                        } else {
                            _tprintf( _T("[x]\t\"%s\" doesn't look like a valid PE file.\n"), sArgs.pszFileName );
                        }
 
                    } else {
                        _tprintf( _T("[x]\tfailed to map view of file.\n") );
                    }

                    CloseHandle( hMap );
                } else {
                    _tprintf( _T("[x]\tfailed to create file mapping.\n") );
                }
            } else {
                _tprintf( _T("[x]\tempty or massive file.\n") );
            }

            CloseHandle( hFile );
            hFile = INVALID_HANDLE_VALUE;
        } else {
            _tprintf( _T("[x]\tfailed to open file \"%s\".\n"), sArgs.pszFileName );
        }
    } else {
        usage( argv[0] );
    }
	return 0;
}

