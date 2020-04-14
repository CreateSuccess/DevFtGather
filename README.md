DevFtGather是基于C++版的设备指纹采集库，根据用户设置的采集要素，HASH运算出设备指纹。目前只支持Window平台，后期提供跨平台支持。

编译库文件方式：
mkdir build 
cd build
cmake ..

window下生成DevFtGather.sln解决方案,DevFtGather为库文件生成的工程
Linux下生成Makefile，运行make即可获得libDevFtGather.a

编译Demo方式：
cd demo
mkdir build 
cd build
cmake ..

window下生成DevFtGather.sln解决方案,DevFtGatherDemo为测试的工程
Linux下生成Makefile，运行make即可获得DevFtGatherDemo




