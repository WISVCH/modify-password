# Modify Password

Provides a simple web form to modify a user's (e.g. your own) LDAP password. 

This application uses the [RFC 3062 LDAP Password Modify Extended Operation][rfc3062] as implemented by the
[Go LDAPv3 library][go-ldap].

[zxcvbn] is used for realistic password strength estimation. The ["Have I Been Pwned" Pwned Passwords list][hibp] is
used to check that a password has not been previously leaked.

This project supersedes the [previous Spring Boot application][password].

 [rfc3062]: https://www.ietf.org/rfc/rfc3062.txt
 [go-ldap]: https://github.com/go-ldap/ldap
 [zxcvbn]: https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/
 [password]: https://github.com/WISVCH/password
 [hibp]: https://haveibeenpwned.com/Passwords
