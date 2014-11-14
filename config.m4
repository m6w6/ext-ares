dnl $Id$
dnl config.m4 for extension ares

PHP_ARG_WITH(ares, [enable asynchronous resolver support],
[  --with-ares             Include asynchronous resolver support])

if test "$PHP_ARES" != "no"; then
	PHP_ARES_DIR=
	AC_MSG_CHECKING(for ares.h)
	for i in "$PHP_ARES" /usr/local /usr; do
		if test -r "$i/include/ares.h"; then
			PHP_ARES_DIR=$i
			AC_MSG_RESULT(found in $i)
			break;
		fi
	done
	if test -z "$PHP_ARES_DIR"; then
		AC_MSG_ERROR(could not find ares.h)
	fi
	
	PHP_ARES_LIB=
	PHP_ARES_LIBADD=
	PHP_CHECK_LIBRARY(cares, ares_init, [
			PHP_ARES_LIB=cares
		], [
			PHP_CHECK_LIBRARY(ares, ares_init, [
					PHP_ARES_LIB=ares
				], [
					PHP_CHECK_LIBRARY(cares, ares_init, [
						PHP_ARES_LIB=cares
						PHP_ARES_LIBADD=rt
					], [
						PHP_CHECK_LIBRARY(ares, ares_init, [
							PHP_ARES_LIB=ares
							PHP_ARES_LIBADD=rt
						], [
							PHP_AREES_LIB=unknown
						], [
							-lrt -L$PHP_ARES_DIR/$PHP_LIBDIR
						])
					], [
						-lrt -L$PHP_ARES_DIR/$PHP_LIBDIR
					])
				], [
					-L$PHP_ARES_DIR/$PHP_LIBDIR
				]
			)
		], [
			-L$PHP_ARES_DIR/$PHP_LIBDIR
		]
	)
	AC_MSG_CHECKING(for libares/libcares)
	AC_MSG_RESULT($PHP_ARES_LIB)
	
	if test "x$PHP_ARES_LIBADD" != "x"; then
		PHP_ADD_LIBRARY(PHP_ARES_LIBADD, 1, ARES_SHARED_LIBADD)
		dnl for later use
		PHP_ARES_LIBADD="-l$PHP_ARES_LIBADD"
	fi
	
	if test $PHP_ARES_LIB = "unknown"; then
		AC_MSG_ERROR(could neither find libares nor libcares)
	elif test $PHP_ARES_LIB = "cares"; then
		AC_DEFINE([PHP_ARES_CARES], [1], [ ])
		AC_DEFINE_UNQUOTED([PHP_ARES_LIBNAME], "c-ares (CURL)", [ ])
		AC_DEFINE([PHP_ARES_EXPAND_LEN_TYPE], [long], [ ])
	else
		AC_DEFINE_UNQUOTED([PHP_ARES_LIBNAME], "ares (MIT)", [ ])
		AC_DEFINE([PHP_ARES_EXPAND_LEN_TYPE], [int], [ ])
		AC_DEFINE([HAVE_OLD_ARES_STRERROR], [1], [ ])
	fi
	
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_cancel, 
		[AC_DEFINE([HAVE_ARES_CANCEL], [1], [ ])], [ ], 
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_getnameinfo, 
		[AC_DEFINE([HAVE_ARES_GETNAMEINFO], [1], [ ])], [ ], 
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_getsock, 
		[AC_DEFINE([HAVE_ARES_GETSOCK], [1], [ ])], [ ], 
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_version,
		[AC_DEFINE([HAVE_ARES_VERSION], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_library_init,
		[AC_DEFINE([HAVE_ARES_LIBRARY_INIT], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_library_cleanup,
		[AC_DEFINE([HAVE_ARES_LIBRARY_CLEANUP], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_set_local_dev,
		[AC_DEFINE([HAVE_ARES_SET_LOCAL_DEV], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_set_local_ip4,
		[AC_DEFINE([HAVE_ARES_SET_LOCAL_IP4], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_set_local_ip6,
		[AC_DEFINE([HAVE_ARES_SET_LOCAL_IP6], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_inet_ntop,
		[AC_DEFINE([HAVE_ARES_INET_NTOP], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_inet_pton,
		[AC_DEFINE([HAVE_ARES_INET_NTOP], [1], [ ])], [ ],
		[$PHP_ARES_LIBADD -L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	
	dnl ##########
	dnl check new c-ares callback API
	dnl ##########
	save_LIBS=$LIBS
	save_CFLAGS=$CFLAGS
	LIBS="-L$PHP_ARES_DIR/$PHP_LIBDIR -l$PHP_ARES_LIB $PHP_ARES_LIBADD"
	CFLAGS="-I$PHP_ARES_DIR/include -Werror"
	
	AC_MSG_CHECKING(for new c-ares callback API)
	AC_TRY_COMPILE(
		[#include <ares.h>
		], [
			ares_search(0, 0, 0, 0, (void (*)(void *, int, int, unsigned char *, int)) 0, 0);
		], [
			AC_MSG_RESULT(yes)
			AC_DEFINE([PHP_ARES_NEW_CALLBACK_API], [1], [ ])
		], [
			AC_MSG_RESULT(no)
			AC_DEFINE([PHP_ARES_NEW_CALLBACK_API], [0], [ ])
		]
	)
	
	LIBS=$save_LIBS
	CFLAGS=$save_CFLAGS
	
	AC_CHECK_HEADERS([netdb.h unistd.h arpa/inet.h arpa/nameser.h arpa/nameser_compat.h])
	
	PHP_ADD_INCLUDE($PHP_ARES_DIR/include)
	PHP_ADD_LIBRARY_WITH_PATH($PHP_ARES_LIB, $PHP_ARES_DIR/$PHP_LIBDIR, ARES_SHARED_LIBADD)
	
	PHP_SUBST(ARES_SHARED_LIBADD)
	PHP_NEW_EXTENSION(ares, php_ares.c, $ext_shared)
fi
