#ifndef __DEV_FT_GATHER_H
#define __DEV_FT_GATHER_H

/***************************************************************************
 * Copyright (c) 1996 - 2020, Wang jianbin, <869538952@qq.com>
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. 
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <stdio.h>
#include <string>
#include <iostream>
#include "CjsonObject.hpp"

/* 采集要素 */
#define DEVFTINFO_MAC          (0x01)  // 采集MAC
#define DEVFTINFO_CPUID        (0x02)  // 采集CPUID操作码
#define DEVFTINFO_UUID         (0x08)  // 采集主板UUID

namespace devFtGathere
{

class DevFtGather
{
public:
    DevFtGather();
    DevFtGather(unsigned long ulDevInfo);
    ~DevFtGather();

public:
    int SetDevInfoList(unsigned long ulDevInfo);
    int GetDevInfo(std::string &strDevInfo);
    int GetDevFt(std::string &strDevFt);

//private:
    std::string GetDevFtInfoMac();
    std::string GetDevFtInfoCpuId();
    std::string GetDevFtInfoUUID();

private:
    unsigned long m_ulDevInfo;
};

}



#endif