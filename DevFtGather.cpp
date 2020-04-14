#include "DevFtGather.h"
#include "arithmetic.h"

#if WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <tchar.h>
#include <conio.h>
#include <stdio.h>
#pragma comment (lib,"iphlpapi")
#pragma comment (lib,"Ws2_32")

#else

#endif


#ifdef _MSC_VER
#define snprintf _snprintf
#endif


namespace devFtGathere
{

DevFtGather::DevFtGather()
    : m_ulDevInfo(0)
{

}

DevFtGather::DevFtGather(unsigned long ulDevInfo)
{
    m_ulDevInfo = ulDevInfo;
}

DevFtGather::~DevFtGather()
{

}

int DevFtGather::SetDevInfoList(unsigned long ulDevInfo)
{
    m_ulDevInfo = ulDevInfo;
    return 0;
}

int DevFtGather::GetDevInfo(std::string &strDevInfo)
{
    neb::CJsonObject oJson;

    oJson.AddEmptySubArray("params");

    if(m_ulDevInfo & DEVFTINFO_MAC)
    {
        neb::CJsonObject oJsonMac(GetDevFtInfoMac());
        oJson["params"].Add(oJsonMac);
    }

    if(m_ulDevInfo & DEVFTINFO_CPUID)
    {
        neb::CJsonObject oJsonCpuId(GetDevFtInfoCpuId());
        oJson["params"].Add(oJsonCpuId);
    }

    if(m_ulDevInfo & DEVFTINFO_UUID)
    {
        neb::CJsonObject oJsonUUID(GetDevFtInfoUUID());
        oJson["params"].Add(oJsonUUID);
    }

    strDevInfo = oJson.ToFormattedString();

    return 0;
}

int DevFtGather::GetDevFt(std::string &strDevFt)
{
    std::string strDevInfo;
    unsigned char pucdigest[SM3_HASH_SIZE];
    char pcdigest[SM3_HASH_SIZE*2]  = {0};


    GetDevInfo(strDevInfo);
    QCard_Sm3((const unsigned char *)strDevInfo.c_str(), strlen(strDevInfo.c_str()), pucdigest);
    QCard_Base64Encry(pucdigest, SM3_HASH_SIZE, (unsigned char *)pcdigest);

    strDevFt = pcdigest;
    return 0;
}

std::string DevFtGather::GetDevFtInfoMac()
{
   MIB_IPADDRTABLE* pIPAddrTable = (MIB_IPADDRTABLE*)malloc(sizeof(MIB_IPADDRTABLE));
   ULONG dwSize = 0,dwRetVal = 0;
   neb::CJsonObject oJson;

   oJson.Add("paramType", "MAC");

   if (GetIpAddrTable(pIPAddrTable,&dwSize,0)==ERROR_INSUFFICIENT_BUFFER)
   {
      free(pIPAddrTable);
      pIPAddrTable=(MIB_IPADDRTABLE*)malloc(dwSize);
   }
   if((dwRetVal=GetIpAddrTable(pIPAddrTable,&dwSize,0))==NO_ERROR)
   {
        ULONG ulHostIp=ntohl(pIPAddrTable->table[0].dwAddr);
        // 获取主机ip地址和子网掩码
        ULONG ulHostMask=ntohl(pIPAddrTable->table[0].dwMask);
        ULONG J = (~ulHostMask);
        for(ULONG I=1;I<(~ulHostMask);I++)
        {
            static ULONG uNo=0;
            HRESULT hr;
            IPAddr ipAddr;
            ULONG pulMac[2];
            ULONG ullen;
            ipAddr=htonl(I+(ulHostIp&ulHostMask));
            memset(pulMac,0xff,sizeof(pulMac));
            ullen=6;
            hr=SendARP(ipAddr,0,pulMac,&ullen);// 探测主机MAC地址
            if(ullen==6)
            {
                PBYTE pbHexMac=(PBYTE)pulMac;
                unsigned char * strIpAddr=(unsigned char *)(&ipAddr);
                char pcMac[1024] ={0};
                snprintf(pcMac, sizeof(pcMac), "%02X:%02X:%02X:%02X:%02X:%02X", pbHexMac[0],pbHexMac[1],pbHexMac[2],pbHexMac[3],pbHexMac[4],pbHexMac[5]);
                oJson.Add("paramValue", pcMac);
                break;
            }
        }
    }
    free(pIPAddrTable);
    return oJson.ToString();
}

std::string DevFtGather::GetDevFtInfoCpuId()
{
    std::string strCPUId;
    unsigned long s1, s2;
    char buf[32] = {0};
    neb::CJsonObject oJson;

    oJson.Add("paramType", "CPUID");
    
    __asm{
        mov eax,01h   //eax=1:取CPU序列号
        xor edx,edx
        cpuid
        mov s1,edx
        mov s2,eax
    }
    if (s1) {
        memset(buf, 0, 32);
        sprintf_s(buf, 32, "%08X", s1);
        strCPUId += buf;
    }
    if (s2) {
        memset(buf, 0, 32);
        sprintf_s(buf, 32, "%08X", s2);
        strCPUId += buf;
    }

    __asm{
        mov eax,03h
        xor ecx,ecx
        xor edx,edx
        cpuid
        mov s1,edx
        mov s2,ecx
    }
    if (s1) {
        memset(buf, 0, 32);
        sprintf_s(buf, 32, "%08X", s1);
        strCPUId += buf;
    }
    if (s2) {
        memset(buf, 0, 32);
        sprintf_s(buf, 32, "%08X", s2);
        strCPUId += buf;
    }
    oJson.Add("paramValue", strCPUId);
    return oJson.ToString();
}

std::string DevFtGather::GetDevFtInfoUUID()
{
    const long MAX_COMMAND_SIZE = 10000; // 命令行输出缓冲大小
#ifdef UNICODE
WCHAR szFetCmd[] = L"wmic csproduct get UUID"; // 获取BOIS命令行   
#else
	LPSTR szFetCmd= "wmic csproduct get UUID" ; // 获取BOIS命令行   
#endif // !UNICODE
     
    const std::string strEnSearch = "UUID"; // 主板序列号的前导信息
    neb::CJsonObject oJson;
    char lpszBaseBoard[1024] = {0};

    oJson.Add("paramType", "CPUID");

    BOOL   bret = FALSE;
    HANDLE hReadPipe = NULL; //读取管道
    HANDLE hWritePipe = NULL; //写入管道    
    PROCESS_INFORMATION pi; //进程信息    
    memset(&pi, 0, sizeof(pi));
    STARTUPINFO    si;    //控制命令行窗口信息
    memset(&si, 0, sizeof(si));
    SECURITY_ATTRIBUTES sa; //安全属性
    memset(&sa, 0, sizeof(sa));

    char szBuffer[MAX_COMMAND_SIZE + 1] = { 0 }; // 放置命令行结果的输出缓冲区
    std::string    strBuffer;
    unsigned long count = 0;
    long ipos = 0;

    pi.hProcess = NULL;
    pi.hThread = NULL;
    si.cb = sizeof(STARTUPINFO);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    //1.创建管道
    bret = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
    if (!bret) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        oJson.Add("paramValue", "NULL");
        return oJson.ToString();
    }

    //2.设置命令行窗口的信息为指定的读写管道
    GetStartupInfo(&si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.wShowWindow = SW_HIDE; //隐藏命令行窗口
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

    //3.创建获取命令行的进程
    bret = CreateProcess(NULL, szFetCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (!bret) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        oJson.Add("paramValue", "NULL");
        return oJson.ToString();
    }

    //4.读取返回的数据
    WaitForSingleObject(pi.hProcess, 200);
    bret = ReadFile(hReadPipe, szBuffer, MAX_COMMAND_SIZE, &count, 0);
    if (!bret) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        oJson.Add("paramValue", "NULL");
        return oJson.ToString();
    }

    //5.查找主板ID
    bret = FALSE;
    strBuffer = szBuffer;
    ipos = strBuffer.find(strEnSearch);

    if (ipos < 0){ 
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        oJson.Add("paramValue", "NULL");
        return oJson.ToString();
    } else {
        strBuffer = strBuffer.substr(ipos + strEnSearch.length());
    }

    memset(szBuffer, 0x00, sizeof(szBuffer));
    strcpy_s(szBuffer, strBuffer.c_str());

    //去掉中间的空格 \r \n
    int j = 0;
    for (int i = 0; i < strlen(szBuffer); i++) {
        if (szBuffer[i] != ' ' && szBuffer[i] != '\n' && szBuffer[i] != '\r') {
            lpszBaseBoard[j] = szBuffer[i];
            j++;
        }
    }

    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    oJson.Add("paramValue", lpszBaseBoard);
    return oJson.ToString();
}

}