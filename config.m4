dnl $Id$
dnl config.m4 for extension kadm5

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(kadm5, for kadm5 support,
dnl Make sure that the comment is aligned:
[  --with-kadm5             Include kadm5 support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(kadm5, whether to enable kadm5 support,
dnl Make sure that the comment is aligned:
dnl [  --enable-kadm5           Enable kadm5 support])

if test "$PHP_KADM5" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-kadm5 -> check with-path
  SEARCH_PATH="/usr/local/include /usr/include /usr/src/krb5-1.2.4/src/include"
  SEARCH_FOR="kadm5/admin.h"
  if test -r $PHP_KADM5/; then # path given as parameter
     KADM5_DIR=$PHP_KADM5
  else # search default path list
     AC_MSG_CHECKING(for kadm5 files in default path)
     for i in $SEARCH_PATH ; do
       if test -r $i/$SEARCH_FOR; then
         KADM5_DIR=$i
         AC_MSG_RESULT(found in $i)
       fi
     done
  fi

  if test -z "$KADM5_DIR"; then
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR(Please reinstall the kadm5 distribution)
  fi

  # --with-kadm5 -> add include path
  PHP_ADD_INCLUDE($KADM5_DIR)
  PHP_ADD_INCLUDE($KADM5_DIR/krb5)
  PHP_ADD_INCLUDE($KADM5_DIR/et)

  # --with-kadm5 -> chech for lib and symbol presence
  LIBNAME=kadm5srv # you may want to change this
  LIBSYMBOL=kadm5 # you most likely want to change this
  old_LIBS=$LIBS
  LIBS="$LIBS -L/usr/lib -lm -ldl"
  dnl AC_CHECK_LIB($LIBNAME, $LIBSYMBOL, [AC_DEFINE(HAVE_KADM5LIB,1,[ ])],
  dnl [AC_MSG_ERROR(wrong kadm5 lib version or lib not found)])
  LIBS=$old_LIBS

  PHP_SUBST(KADM5_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(kadm5clnt, /usr/lib, KADM5_SHARED_LIBADD)
  dnl PHP_ADD_LIBRARY_WITH_PATH(kdb5, /usr/lib, KADM5_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(gssrpc, /usr/lib, KADM5_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(krb5, /usr/lib, KADM5_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH(k5crypto, /usr/lib, KADM5_SHARED_LIBADD)
  dnl PHP_ADD_LIBRARY_WITH_PATH(dyn, /usr/lib, KADM5_SHARED_LIBADD)

  PHP_EXTENSION(kadm5, $ext_shared)
fi
