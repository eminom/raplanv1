from distutils.core import setup, Extension

module1 = Extension('RapLanV1',
    sources = ['rapv1.cpp'
        ,'rapv1ex.cpp'
        ,'netstru.cpp'
        ,'dproc.cpp'
        ,'ipohmac.cpp'
        ,'py3pcapif.cpp'
        ,'py3ifman.cpp'
        ,'py3pque.cpp'
                    	],
                    include_dirs= ["F:/Develop/WpdPack4.1.2/Include","C:/Boost/include/boost-1_57"],
                    define_macros = [("WIN32",None),
                    			("WPCAP",None),
                    			("HAVE_REMOTE",None)],
                    library_dirs = ["F:/Develop/WpdPack4.1.2/Lib/x64"],
                    libraries = ["wpcap","ws2_32","iphlpapi"],
                    extra_compile_args = ["/EHsc"]
                    )

setup (name = 'RapperLan',
       version = '1.0',
       description = "You may be gone, but you're never over.",
       author = 'Eminem',
       author_email = 'eminem7409@hotmail.com',
       ext_modules = [module1])
