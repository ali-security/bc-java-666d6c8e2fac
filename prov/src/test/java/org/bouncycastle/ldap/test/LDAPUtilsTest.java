package org.bouncycastle.ldap.test;

import junit.framework.TestCase;
import org.bouncycastle.ldap.LDAPUtils;

/**
 * Checks that values extracted from a DN by {@link LDAPUtils#parseDN(String, String)} are
 * escaped (RFC 2254) before being placed in an LDAP search filter.
 */
public class LDAPUtilsTest
    extends TestCase
{
    public void testFilterSpecialCharactersAreEscaped()
    {
        assertEquals("\\2a\\28\\29\\5c\\00", LDAPUtils.parseDN("CN=*()\\\0", "CN"));
    }

    public void testInjectedFilterComponentIsEscaped()
    {
        // an attacker supplied RDN value trying to close the assertion and add its own
        assertEquals("x\\2a\\29\\28cn=admin", LDAPUtils.parseDN("CN=x*)(cn=admin", "cn"));
        assertEquals("x\\2a\\29\\28|\\28objectClass=\\2a\\29", LDAPUtils.parseDN("CN=x*)(|(objectClass=*)", "CN"));
    }

    public void testWildcardIsEscaped()
    {
        assertEquals("\\2a", LDAPUtils.parseDN("CN=*", "CN"));
        assertEquals("a\\2ab", LDAPUtils.parseDN("CN=a*b, O=Test", "CN"));
    }

    public void testBackslashIsEscaped()
    {
        assertEquals("a\\5cb", LDAPUtils.parseDN("CN=a\\b", "CN"));
        assertEquals("\\5c2a", LDAPUtils.parseDN("CN=\\2a", "CN"));
    }

    public void testNulIsEscaped()
    {
        assertEquals("a\\00b", LDAPUtils.parseDN("CN=a\0b", "CN"));
    }

    public void testQuotedRFC1779Value()
    {
        // X500Principal.getName("RFC1779") quotes values containing '='
        assertEquals("x\\2a\\29\\28cn=admin", LDAPUtils.parseDN("CN=\"x*)(cn=admin\", O=Test, C=AU", "CN"));
    }

    public void testSelectsRequestedAttribute()
    {
        assertEquals("Evil\\2aCorp", LDAPUtils.parseDN("CN=Alice, O=Evil*Corp, C=US", "O"));
        assertEquals("Alice", LDAPUtils.parseDN("CN=Alice, O=Evil*Corp, C=US", "cn"));
    }

    public void testLeadingSpaceIsRemoved()
    {
        assertEquals("x\\2a", LDAPUtils.parseDN("CN= x*", "CN"));
    }

    public void testEscapedCommaKeptInValue()
    {
        assertEquals("a\\5c,b\\2a", LDAPUtils.parseDN("CN=a\\,b*, O=Test", "CN"));
    }

    public void testOrdinaryValuesUnchanged()
    {
        assertEquals("Bouncy Castle", LDAPUtils.parseDN("O=Bouncy Castle, C=AU", "O"));
        assertEquals("über-été", LDAPUtils.parseDN("CN=über-été", "CN"));
    }

    public void testMissingAttributeGivesEmptyValue()
    {
        assertEquals("", LDAPUtils.parseDN("O=Test, C=AU", "CN"));
    }
}
