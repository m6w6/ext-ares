dnl $Id$
dnl config.m4 for extension ares

PHP_ARG_WITH(ares, for asynchronous resolver support,
[  --with-ares             Include asynchronous resolver support])
PHP_ARG_WITH(ares-lib, type of ares library (cares),
[  --with-ares-lib         MIT/ares or CURL/cares], "cares", "cares")

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
	
	case "$PHP_ARES_LIB" in
		MIT* [)]
			PHP_ARES_LIB=ares
			;;
		ares [)]
			;;
		CURL* [)]
			PHP_ARES_LIB=cares
			;;
		cares [)]
			;;
		* [)]
			PHP_ARES_LIB=cares
			;;
	esac
	
	if test $PHP_ARES_LIB = "cares"; then
		AC_DEFINE_UNQUOTED([PHP_ARES_LIBNAME], "c-ares (CURL)", [ ])
		AC_DEFINE([PHP_ARES_EXPAND_LEN_TYPE], [long], [ ])
	else
		AC_DEFINE_UNQUOTED([PHP_ARES_LIBNAME], "ares (MIT)", [ ])
		AC_DEFINE([PHP_ARES_EXPAND_LEN_TYPE], [int], [ ])
	fi
	
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_cancel, 
		[AC_DEFINE([HAVE_ARES_CANCEL], [1], [ ])], [ ], 
		[-L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_getnameinfo, 
		[AC_DEFINE([HAVE_ARES_GETNAMEINFO], [1], [ ])], [ ], 
		[-L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_expand_string, 
		[AC_DEFINE([HAVE_ARES_EXPAND_STRING], [1], [ ])], [ ], 
		[-L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_parse_aaaa_reply, 
		[AC_DEFINE([HAVE_ARES_PARSE_AAAA_REPLY], [1], [ ])], [ ], 
		[-L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_getsock, 
		[AC_DEFINE([HAVE_ARES_GETSOCK], [1], [ ])], [ ], 
		[-L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	PHP_CHECK_LIBRARY($PHP_ARES_LIB, ares_version, 
		[AC_DEFINE([HAVE_ARES_VERSION], [1], [ ])], [ ], 
		[-L$PHP_ARES_DIR/$PHP_LIBDIR]
	)
	
	AC_CHECK_HEADERS([netdb.h unistd.h arpa/inet.h arpa/nameser.h])
	PHP_ADD_INCLUDE($PHP_ARES_DIR/include)
	PHP_ADD_LIBRARY_WITH_PATH($PHP_ARES_LIB, $PHP_ARES_DIR/$PHP_LIBDIR, ARES_SHARED_LIBADD)
	PHP_SUBST(ARES_SHARED_LIBADD)
	PHP_NEW_EXTENSION(ares, ares.c, $ext_shared)
fi
