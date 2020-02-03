PHP_ARG_WITH(kadm5, for kadm5 support,
dnl Make sure that the comment is aligned:
[  --with-kadm5             Include kadm5 support])

if test "$PHP_KADM5" != "no"; then
  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  KRB5_REQUIRED=1.12.1

  if test -x "$PKG_CONFIG" && $PKG_CONFIG kadm-client --exists ; then
    AC_MSG_CHECKING(kadm-client version)
    if $PKG_CONFIG kadm-client --atleast-version=$KRB5_REQUIRED ; then
      KADMCLNT_INCLUDE=`$PKG_CONFIG kadm-client --cflags`
      KADMCLNT_LIBRARY=`$PKG_CONFIG kadm-client --libs`
      KADMCLNT_VERSION=`$PKG_CONFIG kadm-client --modversion`
      AC_MSG_RESULT($KADMCLNT_VERSION)
    else
      AC_MSG_ERROR(version too old)
    fi
    PHP_EVAL_INCLINE($KADMCLNT_INCLUDE)
    PHP_EVAL_LIBLINE($KADMCLNT_LIBRARY, KADM5_SHARED_LIBADD)

    AC_MSG_CHECKING(kadm-server version)
    if $PKG_CONFIG kadm-server --atleast-version=$KRB5_REQUIRED ; then
      KADMSRV_INCLUDE=`$PKG_CONFIG kadm-server --cflags`
      KADMSRV_LIBRARY=`$PKG_CONFIG kadm-server --libs`
      KADMSRV_VERSION=`$PKG_CONFIG kadm-server --modversion`
      AC_MSG_RESULT($KADMSRV_VERSION)
    else
      AC_MSG_ERROR(version too old)
    fi
    PHP_EVAL_INCLINE($KADMSRV_INCLUDE)
    PHP_EVAL_LIBLINE($KADMSRV_LIBRARY, KADM5_SHARED_LIBADD)

    AC_MSG_CHECKING(gssrpc version)
    if $PKG_CONFIG gssrpc --atleast-version=$KRB5_REQUIRED ; then
      GSSRPC_INCLUDE=`$PKG_CONFIG gssrpc --cflags`
      GSSRPC_LIBRARY=`$PKG_CONFIG gssrpc --libs`
      GSSRPC_VERSION=`$PKG_CONFIG gssrpc --modversion`
      AC_MSG_RESULT($GSSRPC_VERSION)
    else
      AC_MSG_ERROR(version too old)
    fi
    PHP_EVAL_INCLINE($GSSRPC_INCLUDE)
    PHP_EVAL_LIBLINE($GSSRPC_LIBRARY, KADM5_SHARED_LIBADD)

    AC_MSG_CHECKING(krb5 version)
    if $PKG_CONFIG krb5 --atleast-version=$KRB5_REQUIRED ; then
      KRB5_INCLUDE=`$PKG_CONFIG krb5 --cflags`
      KRB5_LIBRARY=`$PKG_CONFIG krb5 --libs`
      KRB5_VERSION=`$PKG_CONFIG krb5 --modversion`
      AC_MSG_RESULT($KRB5_VERSION)
    else
      AC_MSG_ERROR(version too old)
    fi
    PHP_EVAL_INCLINE($KRB5_INCLUDE)
    PHP_EVAL_LIBLINE($KRB5_LIBRARY, KADM5_SHARED_LIBADD)

    PHP_NEW_EXTENSION(kadm5, kadm5.c, $ext_shared)
    PHP_SUBST(KADM5_SHARED_LIBADD)
  else
    AC_MSG_ERROR(pkg-config not found)
  fi
fi
