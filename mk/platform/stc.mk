OP_DEFINES += -D_GNU_SOURCE

#OP_CXXFLAGS := $(OP_CXXFLAGS) --sysroot=/export/crosstools/spirent-yocto-1.5/x86_64/target\
#        -I/export/crosstools/spirent-yocto-1.5/x86_64/target/usr/include/c++ \
#        -I/export/crosstools/spirent-yocto-1.5/x86_64/target/usr/include/c++/backward \
#        -I/export/crosstools/spirent-yocto-1.5/x86_64/target/usr/include/c++/x86_64 \
#        -I/export/crosstools/spirent-yocto-1.5/x86_64/target/user/include
OP_CXXOPTS := $(OP_CXXOPTS) --sysroot=/export/crosstools/spirent-yocto-1.5/x86_64/target \
        -nostdinc++ \
        -cxx-isystem /export/crosstools/spirent-yocto-1.5/x86_64/x86_64-spirent-linux/include/c++/8.2.0 \
        -cxx-isystem /export/crosstools/spirent-yocto-1.5/x86_64/x86_64-spirent-linux/include/c++/8.2.0/x86_64-spirent-linux
#        -I/home/dmorton/openperf \
#       -include force_link_glibc_2.18.h \
#        -cxx-isystem /export/crosstools/spirent-yocto-1.5/x86_64/target/usr/include \
#        -cxx-isystem /export/crosstools/spirent-yocto-1.5/x86_64/target/usr/include/c++ \
#       -cxx-isystem /export/crosstools/spirent-yocto-1.5/x86_64/target/usr/include/c++/x86_64-spirent-linux
#OP_CFLAGS := $(OP_CFLAGS) --sysroot=/export/crosstools/spirent-yocto-1.5/x86_64/target \
#        -I/export/crosstools/spirent-yocto-1.5/x86_64/target/user/include
OP_LDOPTS := $(OP_LDOPTS) --sysroot=/export/crosstools/spirent-yocto-1.5/x86_64/target

OP_COPTS := $(OP_COPTS) --sysroot=/export/crosstools/spirent-yocto-1.5/x86_64/target
#        -I/home/dmorton/openperf \
#       -include force_link_glibc_2.18.h \
#OP_CXXOPTS := $(OP_CXXOPTS) --sysroot=/export/crosstools/spirent-yocto-1.5/x86_64/target
#OP_LDOPTS: := -lmvec 
