#include "DevFtGather.h"
#include "iostream"

using namespace std;

int main()
{
    devFtGathere::DevFtGather Ft(DEVFTINFO_MAC | DEVFTINFO_CPUID | DEVFTINFO_UUID);
    string strFtInfo, strFt;
    Ft.GetDevInfo(strFtInfo);
    Ft.GetDevFt(strFt);
    cout << "设备采集要素:"<< strFtInfo << endl;
    cout << "设备指纹:"<< strFt << endl;
    return 0;
}