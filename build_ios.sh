# Compile for x86_64 simulator architecture
GOARCH=amd64 \                     
SDK=iphonesimulator \           
LIB_NAME=libprove \               
./build_ios_base.sh                   

# Compile for arm64 simulator architecture
GOARCH=arm64 \
SDK=iphonesimulator \
LIB_NAME=libprove \
./build_ios_base.sh

# Compile for arm64 device architecture
GOARCH=arm64 \
SDK=iphoneos \
LIB_NAME=libprove \
./build_ios_base.sh

lipo \
-create \
libsum_arm64_iphonesimulator.a \
libsum_amd64_iphonesimulator.a \
-output libprove_iphonesimulator.a