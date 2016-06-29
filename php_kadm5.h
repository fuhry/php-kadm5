/*
 * php4_kadm5: remote administration of Kerberos Administration Servers
 * Copyright (C) 2003 GONICUS GmbH.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA	 02111-1307	 USA
 *
 * Author:	Holger Burbach <holger.burbach@GONICUS.de>
 *			GONICUS GmbH
 *			Moehnestrasse 11-17
 *			D-59755 Arnsberg
 *			http://www.GONICUS.de
 *
 */

#ifndef PHP_KADM5_H
#define PHP_KADM5_H

extern zend_module_entry kadm5_module_entry;
#define phpext_kadm5_ptr &kadm5_module_entry

#ifdef PHP_WIN32
#define PHP_KADM5_API __declspec(dllexport)
#else
#define PHP_KADM5_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(kadm5);
PHP_MSHUTDOWN_FUNCTION(kadm5);
PHP_MINFO_FUNCTION(kadm5);

PHP_FUNCTION(kadm5_init_with_password);
PHP_FUNCTION(kadm5_destroy);
PHP_FUNCTION(kadm5_flush);
PHP_FUNCTION(kadm5_create_principal);
PHP_FUNCTION(kadm5_delete_principal);
PHP_FUNCTION(kadm5_modify_principal);
PHP_FUNCTION(kadm5_chpass_principal);
PHP_FUNCTION(kadm5_get_principals);
PHP_FUNCTION(kadm5_get_principal);
PHP_FUNCTION(kadm5_get_policies);

#endif	/* PHP_KADM5_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */
