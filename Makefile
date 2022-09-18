netapi32 :
	i686-w64-mingw32-gcc -pipe -Wall -O2 -s -mdll -mwin32 -mwindows \
	-std=c99 -DSUBHOOK_STATIC -o netapi32.dll \
	nyet-modem.c netapi32.def subhook/subhook.c \
	-lws2_32

clean :
	rm netapi32.dll
