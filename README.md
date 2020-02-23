# Active-Directory-Nested-Group-Enumeration

Sysnopsis:
Why? There does not seem to be any means to fully enumerate nested groups. We are supposed to be able to use an specific oid in an ldap filter that does this, namely:
    (memberOf:1.2.840.113556.1.4.1941:=CN=Administrators,CN=Builtin,DC="xxxxxxx",DC="xxxxxx",DC=local,DC=com)
But I've not been able to make that work and it doesn't seem to tell us much about the structure of the nesting. In my testing it only shows about half of the nested users.

This script fully enumerates nested Active Directory groups for a targeted domain provided as an argument. At this time a ini file is employed to list all of the domains in the forest. After some up front work is done to set up some indexes for the domains so they can be called up by samName, fqdn, or DN, the first search is dispatch to AD to get the list of Groups for the Target Domain. That list then becomes the initial seed stack of groups that need to be drilled. As each group memebership is drilled out and users found are tabulated and groups are added to the stack. It's always keeping track of where a group or member came from. The final tabulation includes:

    rootGroup   -Starting point in the Targeted Domain (start of the nested group path).
    path        -Path to the user from the Targeted Domain.
    leafGroup   -Group to which the user belongs to (end of the nested group path).
    user

If you get the impression that it looks like it was written by a mechanical engineer not a programer, good guess on your part.

The account used to run this will of course need enough access to enumerate any group in the AD Forest.

Usage:
Create an ini file, ldap_group_deep_enum_10.ini, that list all domains in the AD Forest
  [domains]
  fqdns='forestRoot.local.com','child1.forestRoot.local.com',child2.forestRoot.local.com'
  sams='forestRoot','child1','child2'

Only one option, "fqdns" or "sams", needs to be used.


Run the script
  C:\scripts.py\active_directory\group_enum>ldap_group_deep_enum_10.py -td "your target domain here"


Future Enhancements:
1. Add code to learn all of the domains in the Forest instead of the ini file.
2. Additionally add code to find the closest domain controller for the ldap connection.
3. Add option to enumerate a specific group or groups.

Techie Details:
There are a few levels of filtering to be aware of. The first level is to filter in all of the security groups in the Targeted domain.
Four samAccountType values where used to grab the initial group list from the Targeted Domain, show with an '*' below. For the drill
down in the the member objects a user is identified as samAccountType=805306368 and a group by 268435456 or 536870912. Any other
samAccountTypes found are written to "debug0". There's no telling what you might find there, machine accounts or distribution groups.

SAM_DOMAIN_OBJECT                   0x0             0
SAM_GROUP_OBJECT                    0x10000000		268435456
SAM_NON_SECURITY_GROUP_OBJECT       0x10000001	    268435457
SAM_ALIAS_OBJECT                    0x20000000		536870912
SAM_NON_SECURITY_ALIAS_OBJECT       0x20000001	    536870913
SAM_USER_OBJECT                     0x30000000		805306368
SAM_NORMAL_USER_ACCOUNT             0x30000000	    805306368
SAM_MACHINE_ACCOUNT                 0x30000001		805306369
SAM_TRUST_ACCOUNT                   0x30000002		805306370
SAM_APP_BASIC_GROUP                 0x40000000		1073741824
SAM_APP_QUERY_GROUP                 0x40000001		1073741825
SAM_ACCOUNT_TYPE_MAX                0x7fffffff		2147483647


Group Scope         Group Type      groupType attribute     sAMAccountType attribute
Universal           Distribution    8                       268435457
Universal           Security        -2147483640*            268435456
Global              Distribution    2                       268435457
Global              Security        -2147483646*            268435456
Domain Local        Distribution    4                       536870913
Domain Local        Security        -2147483644*            536870912
BuiltIn             Security        -2147483643*            536870912

LDAP Escaping Special Characters:
https://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
