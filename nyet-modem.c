/*
 *  SPDX-License-Identifier: GPL-3.0-only
 *
 *  nyet-modem, network wrapper for NWC's Heroes of Might and Magic
 *  Copyright (C) 2021  GranMinigun
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3 of the License only.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define SUBHOOK_STATIC

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "subhook/subhook.h"

// Proxy library

FARPROC origNetbios;

void proxy_dll()
{
    HMODULE orig_lib = LoadLibrary("C:\\Windows\\System32\\netapi32.dll");
    origNetbios = GetProcAddress(orig_lib, "Netbios");

    return;
}

__declspec(naked) void _Netbios()
{
    __asm jmp[origNetbios]
}

// Networking

#define HOST_SERVER 0
#define HOST_CLIENT 1

int host_type = HOST_CLIENT;
WSADATA wsa_data;
SOCKET host_socket, client_socket;
struct addrinfo *result = NULL, *ptr = NULL, hints;

int host_try_accept()
{
    client_socket = accept(host_socket, NULL, NULL);
    if (client_socket == INVALID_SOCKET)
    {
        int err = WSAGetLastError();
        switch (err)
        {
            case WSAEWOULDBLOCK:
                return 0;

            default:
                printf("Failed to accept connection: %d\n", err);
                closesocket(host_socket);
                WSACleanup();

                return 1;
        }
    }

    closesocket(host_socket);

    return 0;
}

int host_try_connect()
{
    if (connect(client_socket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR)
    {
        int err = WSAGetLastError();
        switch (err)
        {
            case WSAEWOULDBLOCK:
            case WSAEALREADY:
                return 0;

            default:
                printf("Failed to connect: %d\n", err);
                closesocket(client_socket);
                client_socket = INVALID_SOCKET;
                WSACleanup();

                return 1;
        }
    }

    freeaddrinfo(result);

    return 0;
}

int host_init()
{
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        printf("Failed to initialize networking\n");
        return 1;
    }

    char *laddr = NULL, *caddr = NULL, *port = NULL;

    FILE *fp = fopen("nyet-modem.cfg", "r");
    if (fp != NULL)
    {
        while (!feof(fp))
        {
            char s[80];
            if (fgets(s, sizeof(s), fp))
            {
                char *p;

                p = strtok(s, "= ");
                if (p)
                {
                    if (!strcmp(p, "mode"))
                    {
                        p = strtok(NULL, "= \n");
                        if (p)
                        {
                            host_type = strcmp(p, "server") ? HOST_CLIENT : HOST_SERVER;
                        }
                        else
                            printf("Failed to retrieve host mode option, falling back to client\n");
                    }
                    else if (!strcmp(p, "listen_address"))
                    {
                        p = strtok(NULL, "= \n");
                        if (!p)
                            printf("Failed to retrieve listen address option, falling back to any address\n");
                        else
                        {
                            laddr = (char *)malloc(strlen(p) + 1);
                            if (laddr != NULL)
                                strcpy(laddr, p);
                            else
                            {
                                printf("Failed to set listen address\n");
                                return 1;
                            }
                        }
                    }
                    else if (!strcmp(p, "connect_address"))
                    {
                        p = strtok(NULL, "= \n");
                        if (!p)
                        {
                            printf("Failed to retrieve connection address option, falling back to localhost\n");

                            caddr = (char *)malloc(10);
                            if (caddr != NULL)
                                strcpy(caddr, "127.0.0.1");
                            else
                            {
                                printf("Failed to set connection address\n");
                                return 1;
                            }
                        }
                        else
                        {
                            caddr = (char *)malloc(strlen(p) + 1);
                            if (caddr != NULL)
                                strcpy(caddr, p);
                            else
                            {
                                printf("Failed to set connection address\n");
                                return 1;
                            }
                        }
                    }
                    else if (!strcmp(p, "port"))
                    {
                        p = strtok(NULL, "= \n");
                        if (!p)
                        {
                            printf("Failed to retrieve port option, falling back to default\n");
                            port = (char *)malloc(6);
                            if (port != NULL)
                                strcpy(port, "52325");
                            else
                            {
                                printf("Failed to set port\n");
                                return 1;
                            }
                        }
                        else
                        {
                            port = (char *)malloc(strlen(p) + 1);
                            if (port != NULL)
                                strcpy(port, p);
                            else
                            {
                                printf("Failed to set port\n");
                                return 1;
                            }
                        }
                    }
                }
            }
        }

        fclose(fp);
    }
    else
    {
        printf("Failed to read configuration\n");
        return 1;
    }

    if (!caddr)
    {
        printf("No connection address option specified, falling back to localhost\n");

        caddr = (char *)malloc(10);
        if (caddr != NULL)
            strcpy(caddr, "127.0.0.1");
        else
        {
            printf("Failed to set connection address\n");
            return 1;
        }
    }

    if (!port)
    {
        printf("No port option specified, falling back to default\n");

        port = (char *)malloc(6);
        if (port != NULL)
            strcpy(port, "52325");
        else
        {
            printf("Failed to set port\n");
            return 1;
        }
    }

    if (host_type == HOST_SERVER)
    {
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        if (getaddrinfo(laddr, port, &hints, &result) != 0)
        {
            printf("Failed to retrieve address info\n");
            WSACleanup();

            return 1;
        }

        host_socket = INVALID_SOCKET;

        host_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (host_socket == INVALID_SOCKET)
        {
            printf("Failed to create socket: %d\n", WSAGetLastError());
            freeaddrinfo(result);
            WSACleanup();

            return 1;
        }

        if (bind(host_socket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR)
        {
            printf("Failed to bind socket: %d\n", WSAGetLastError());
            freeaddrinfo(result);
            closesocket(host_socket);
            WSACleanup();

            return 1;
        }

        freeaddrinfo(result);

        if (listen(host_socket, 1) == SOCKET_ERROR)
        {
            printf("Failed to open listening socket: %d\n", WSAGetLastError());
            closesocket(host_socket);
            WSACleanup();

            return 1;
        }

        {
            u_long iMode = 1;
            if (ioctlsocket(host_socket, FIONBIO, &iMode) != NO_ERROR)
                printf("Failed to set socket as non-blocking\n");
        }

        client_socket = INVALID_SOCKET;

        printf("Server is up and running\n");
    }
    else // Client
    {
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(caddr, port, &hints, &result) != 0)
        {
            printf("Failed to retrieve address info\n");
            WSACleanup();

            return 1;
        }

        ptr = result;
        client_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (client_socket == INVALID_SOCKET)
        {
            printf("Failed to create client socket: %d\n", WSAGetLastError());
            freeaddrinfo(result);
            WSACleanup();

            return 1;
        }

        {
            u_long iMode = 1;
            if (ioctlsocket(client_socket, FIONBIO, &iMode) != NO_ERROR)
                printf("Failed to set socket as non-blocking\n");
        }

        if (host_try_connect() != 0)
            return 1;

        printf("Client is up and running\n");
    }

    if (laddr)
        free(laddr);
    if (caddr)
        free(caddr);
    if (port)
        free(port);

    return 0;
}

void host_destroy()
{
    if (host_socket != INVALID_SOCKET)
        closesocket(host_socket);
    if (client_socket != INVALID_SOCKET)
        closesocket(client_socket);
    WSACleanup();

    return;
}

// Function interception

subhook_t CreateFileHook;
subhook_t WriteFileHook;
subhook_t ReadFileHook;
subhook_t CloseHandleHook;
subhook_t SetupCommHook;
subhook_t GetCommStateHook;
subhook_t SetCommStateHook;
subhook_t GetCommTimeoutsHook;
subhook_t SetCommTimeoutsHook;
subhook_t ClearCommErrorHook;

void setup_hooks()
{
    subhook_install(WriteFileHook);
    subhook_install(ReadFileHook);
    subhook_install(CloseHandleHook);
    subhook_install(SetupCommHook);
    subhook_install(GetCommStateHook);
    subhook_install(SetCommStateHook);
    subhook_install(GetCommTimeoutsHook);
    subhook_install(SetCommTimeoutsHook);
    subhook_install(ClearCommErrorHook);

    return;
}

void remove_hooks()
{
    subhook_remove(WriteFileHook);
    subhook_remove(ReadFileHook);
    subhook_remove(CloseHandleHook);
    subhook_remove(SetupCommHook);
    subhook_remove(GetCommStateHook);
    subhook_remove(SetCommStateHook);
    subhook_remove(GetCommTimeoutsHook);
    subhook_remove(SetCommTimeoutsHook);
    subhook_remove(ClearCommErrorHook);

    return;
}

HANDLE serial;

HANDLE WINAPI _CreateFile(LPCSTR lpFileName,
                          DWORD dwDesiredAccess,
                          DWORD dwShareMode,
                          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                          DWORD dwCreationDisposition,
                          DWORD dwFlagsAndAttributes,
                          HANDLE hTemplateFile)
{
    subhook_remove(CreateFileHook);

    HANDLE out_file;

    if (strcmp(lpFileName, "COM1") == 0
        || strcmp(lpFileName, "COM2") == 0
        || strcmp(lpFileName, "COM3") == 0
        || strcmp(lpFileName, "COM4") == 0)
    {
        printf("Intercepting access to serial port %s\n", lpFileName);

        // FIXME: No need for a file, just a handle
        serial = CreateFile("serial.dmp",
                            dwDesiredAccess,
                            dwShareMode,
                            lpSecurityAttributes,
                            CREATE_ALWAYS,
                            dwFlagsAndAttributes | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                            hTemplateFile);

        if (host_init() != 0)
            return INVALID_HANDLE_VALUE;

        if (serial != INVALID_HANDLE_VALUE)
            setup_hooks();

        out_file = serial;
    }
    else
    {
        out_file = CreateFile(lpFileName,
                              dwDesiredAccess,
                              dwShareMode,
                              lpSecurityAttributes,
                              dwCreationDisposition,
                              dwFlagsAndAttributes,
                              hTemplateFile);
    }

    subhook_install(CreateFileHook);

    return out_file;
}

BOOL WINAPI _WriteFile(HANDLE hFile,
                       LPVOID lpBuffer,
                       DWORD nNumberOfBytesToWrite,
                       LPDWORD lpNumberOfBytesWritten,
                       LPOVERLAPPED lpOverlapped)
{
    if (hFile == serial)
    {
        int r;
        r = send(client_socket, lpBuffer, nNumberOfBytesToWrite, 0);

        if (r == SOCKET_ERROR)
        {
            int err = WSAGetLastError();
            switch (err)
            {
                case WSAENOTSOCK:
                    if (host_type == HOST_SERVER)
                        if (host_try_accept() != 0)
                            return FALSE;
                        else
                        {
                            if (lpNumberOfBytesWritten)
                                *lpNumberOfBytesWritten = nNumberOfBytesToWrite;

                            return TRUE;
                        }

                        printf("Invalid client socket; This should never happen\n");
                        return FALSE;

                        break;

                case WSAENOTCONN:
                    if (host_type == HOST_CLIENT)
                        if (host_try_connect() != 0)
                            return FALSE;
                        else
                        {
                            if (lpNumberOfBytesWritten)
                                *lpNumberOfBytesWritten = nNumberOfBytesToWrite;

                            return TRUE;
                        }

                        printf("No connection from server to client; This should never happen\n");
                        return FALSE;

                        break;

                default:
                    printf("Failed to send data: %d\n", err);
                    return FALSE;
            }
        }
        else
        {
            if (lpNumberOfBytesWritten)
                *lpNumberOfBytesWritten = r;

            return TRUE;
        }
    }
    else
    {
        subhook_remove(WriteFileHook);

        BOOL out;
        out = WriteFile(hFile,
                        lpBuffer,
                        nNumberOfBytesToWrite,
                        lpNumberOfBytesWritten,
                        lpOverlapped);

        subhook_install(WriteFileHook);

        return out;
    }
}

BOOL WINAPI _ReadFile(HANDLE hFile,
                      LPVOID lpBuffer,
                      DWORD nNumberOfBytesToRead,
                      LPDWORD lpNumberOfBytesRead,
                      LPOVERLAPPED lpOverlapped)
{
    BOOL out;

    if (hFile == serial)
    {
        int r;
        r = recv(client_socket, lpBuffer, nNumberOfBytesToRead, 0);

        if (lpNumberOfBytesRead)
            *lpNumberOfBytesRead = r;

        out = TRUE;
    }
    else
    {
        subhook_remove(ReadFileHook);
        out = ReadFile(hFile,
                       lpBuffer,
                       nNumberOfBytesToRead,
                       lpNumberOfBytesRead,
                       lpOverlapped);
        subhook_install(ReadFileHook);
    }

    return out;
}

BOOL WINAPI _CloseHandle(HANDLE hObject)
{
    if (hObject == serial)
    {
        host_destroy();
        remove_hooks();

        return CloseHandle(hObject);
    }

    subhook_remove(CloseHandleHook);
    BOOL out = CloseHandle(hObject);
    subhook_install(CloseHandleHook);

    return out;
}

// Polling
BOOL WINAPI _ClearCommError(HANDLE hFile, LPDWORD lpErrors, LPCOMSTAT lpStat)
{
    if (lpStat)
        ioctlsocket(client_socket, FIONREAD, &lpStat->cbInQue);

    return TRUE;
}

BOOL WINAPI _SetupComm(HANDLE hFile, DWORD dwInQueue, DWORD dwOutQueue)
{
    return TRUE;
}

BOOL WINAPI _GetCommState(HANDLE hFile, LPDCB lpDCB)
{
    return TRUE;
}

BOOL WINAPI _SetCommState(HANDLE hFile, LPDCB lpDCB)
{
    return TRUE;
}

BOOL WINAPI _GetCommTimeouts(HANDLE hFile, LPCOMMTIMEOUTS lpCommTimeouts)
{
    return TRUE;
}

BOOL WINAPI _SetCommTimeouts(HANDLE hFile, LPCOMMTIMEOUTS lpCommTimeouts)
{
    return TRUE;
}

void init_hooks()
{
    CreateFileHook = subhook_new((void *)CreateFile, (void *)_CreateFile, 0);
    WriteFileHook = subhook_new((void *)WriteFile, (void *)_WriteFile, 0);
    ReadFileHook = subhook_new((void *)ReadFile, (void *)_ReadFile, 0);
    CloseHandleHook = subhook_new((void *)CloseHandle, (void *)_CloseHandle, 0);
    SetupCommHook = subhook_new((void *)SetupComm, (void *)_SetupComm, 0);
    SetCommStateHook = subhook_new((void *)SetCommState, (void *)_SetCommState, 0);
    GetCommTimeoutsHook = subhook_new((void *)GetCommTimeouts, (void *)_GetCommTimeouts, 0);
    SetCommTimeoutsHook = subhook_new((void *)SetCommTimeouts, (void *)_SetCommTimeouts, 0);
    ClearCommErrorHook = subhook_new((void *)ClearCommError, (void *)_ClearCommError, 0);
    GetCommStateHook = subhook_new((void *)GetCommState, (void *)_GetCommState, 0);

    return;
}

void deinit_hooks()
{
    subhook_free(WriteFileHook);
    subhook_free(ReadFileHook);
    subhook_free(CloseHandleHook);
    subhook_free(SetupCommHook);
    subhook_free(GetCommStateHook);
    subhook_free(SetCommStateHook);
    subhook_free(GetCommTimeoutsHook);
    subhook_free(SetCommTimeoutsHook);
    subhook_free(ClearCommErrorHook);

    return;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            proxy_dll();
            init_hooks();
            subhook_install(CreateFileHook);
            break;

        case DLL_PROCESS_DETACH:
            subhook_remove(CreateFileHook);
            subhook_free(CreateFileHook);
            deinit_hooks();
            break;
    }

    return TRUE;
}
