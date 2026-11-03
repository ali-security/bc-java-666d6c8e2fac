package org.bouncycastle.ldap.test;

import java.net.InetAddress;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Filter;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.AttributeCertificateHolder;
import org.bouncycastle.x509.X509AttributeCertStoreSelector;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509CertPairStoreSelector;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.X509Store;
import org.bouncycastle.x509.util.LDAPStoreHelper;

/**
 * LDAP filter injection through attacker controlled subject/issuer DN attribute values.
 * <p>
 * A DN attribute value is copied into the search filter sent to the directory. Unless the
 * value is escaped, filter metacharacters in it ('*', '(', ')', '\', NUL) change the structure
 * of the search. The in-memory directory below records the filters it actually receives so
 * we can check the value arrives as a single literal assertion value.
 */
public class LDAPStoreHelperTest
    extends TestCase
{
    private static final String BASE_DN = "dc=test";

    /**
     * Closes the substring assertion and adds a second filter component of its own.
     */
    private static final String INJECTION = "x*)(cn=admin";

    /**
     * A bare wildcard, which unescaped would match every entry in the directory.
     */
    private static final String WILDCARD = "*";

    private InMemoryDirectoryServer ds;
    private FilterRecorder recorder;
    private String ldapURL;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        recorder = new FilterRecorder();

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE_DN);
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default",
            InetAddress.getByName("127.0.0.1"), 0, null));
        config.setSchema(null);
        config.addInMemoryOperationInterceptor(recorder);

        ds = new InMemoryDirectoryServer(config);
        ds.add("dn: " + BASE_DN, "objectClass: top", "objectClass: domain", "dc: test");
        ds.startListening();

        ldapURL = "ldap://127.0.0.1:" + ds.getListenPort();
    }

    public void tearDown()
    {
        if (ds != null)
        {
            ds.shutDown(true);
        }
    }

    public void testUserCertificatesSubjectInjection()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(name(BCStyle.CN, INJECTION).getEncoded());

        helper.getUserCertificates(selector);

        checkLiteralSearch("cn", INJECTION);
    }

    public void testUserCertificatesSubjectWildcard()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(name(BCStyle.CN, WILDCARD).getEncoded());

        helper.getUserCertificates(selector);

        checkLiteralSearch("cn", WILDCARD);
    }

    public void testCACertificatesSubjectInjection()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(name(BCStyle.O, INJECTION).getEncoded());

        helper.getCACertificates(selector);

        checkLiteralSearch("o", INJECTION);
    }

    public void testCrossCertificatePairsSubjectInjection()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509CertStoreSelector forward = new X509CertStoreSelector();
        forward.setSubject(name(BCStyle.O, INJECTION).getEncoded());
        X509CertPairStoreSelector selector = new X509CertPairStoreSelector();
        selector.setForwardSelector(forward);

        helper.getCrossCertificatePairs(selector);

        checkLiteralSearch("o", INJECTION);
    }

    public void testAACertificatesHolderInjection()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509AttributeCertStoreSelector selector = new X509AttributeCertStoreSelector();
        selector.setHolder(new AttributeCertificateHolder(name(BCStyle.O, INJECTION)));

        helper.getAACertificates(selector);

        checkLiteralSearch("o", INJECTION);
    }

    public void testAttributeCertificateAttributesHolderInjection()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509AttributeCertStoreSelector selector = new X509AttributeCertStoreSelector();
        selector.setHolder(new AttributeCertificateHolder(name(BCStyle.CN, INJECTION)));

        helper.getAttributeCertificateAttributes(selector);

        checkLiteralSearch("cn", INJECTION);
    }

    public void testCRLIssuerInjection()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509CRLStoreSelector selector = new X509CRLStoreSelector();
        selector.addIssuer(name(BCStyle.O, INJECTION));

        helper.getCertificateRevocationLists(selector);

        checkLiteralSearch("o", INJECTION);
    }

    public void testDeltaCRLIssuerInjection()
        throws Exception
    {
        LDAPStoreHelper helper = new LDAPStoreHelper(defaultParameters());

        X509CRLStoreSelector selector = new X509CRLStoreSelector();
        selector.addIssuer(name(BCStyle.O, INJECTION));

        helper.getDeltaCertificateRevocationLists(selector);

        checkLiteralSearch("o", INJECTION);
    }

    public void testX509StoreCertificateSubjectInjection()
        throws Exception
    {
        X509Store store = X509Store.getInstance("CERTIFICATE/LDAP", defaultParameters(), "BC");

        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(name(BCStyle.CN, INJECTION).getEncoded());

        store.getMatches(selector);

        checkLiteralSearch("cn", INJECTION);
    }

    public void testCertStoreCertificateSubjectInjection()
        throws Exception
    {
        CertStore store = CertStore.getInstance("LDAP", singleAttributeParameters(), "BC");

        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(name(BCStyle.CN, INJECTION));

        store.getCertificates(selector);

        checkLiteralSearch("cn", INJECTION);
    }

    public void testCertStoreCRLIssuerInjection()
        throws Exception
    {
        CertStore store = CertStore.getInstance("LDAP", singleAttributeParameters(), "BC");

        X509CRLSelector selector = new X509CRLSelector();
        selector.addIssuer(name(BCStyle.O, INJECTION));

        store.getCRLs(selector);

        checkLiteralSearch("o", INJECTION);
    }

    private X509LDAPCertStoreParameters defaultParameters()
    {
        return new X509LDAPCertStoreParameters.Builder(ldapURL, BASE_DN).build();
    }

    /*
     * X509LDAPCertStoreSpi only takes a single attribute name per search.
     */
    private X509LDAPCertStoreParameters singleAttributeParameters()
    {
        return new X509LDAPCertStoreParameters.Builder(ldapURL, BASE_DN)
            .setLdapCACertificateAttributeName("cn")
            .setCACertificateSubjectAttributeName("cn")
            .setLdapCrossCertificateAttributeName("cn")
            .setCrossCertificateSubjectAttributeName("cn")
            .setLdapCertificateRevocationListAttributeName("o")
            .setCertificateRevocationListIssuerAttributeName("o")
            .build();
    }

    private static X500Principal name(ASN1ObjectIdentifier attr, String value)
        throws Exception
    {
        return new X500Principal(new X500NameBuilder(BCStyle.INSTANCE).addRDN(attr, value).build().getEncoded());
    }

    /**
     * The directory must have received a search for the attacker supplied value as a single
     * literal substring assertion ("*value*") on the attribute, and nothing injected beside it.
     */
    private void checkLiteralSearch(String attrName, String value)
    {
        List<Filter> filters = recorder.getFilters();

        assertFalse("no search reached the directory", filters.isEmpty());

        boolean found = false;
        for (int i = 0; i != filters.size(); i++)
        {
            Filter filter = (Filter)filters.get(i);

            checkNoInjectedComponent(filter, value);

            found |= containsLiteralSubstring(filter, attrName, value);
        }

        assertTrue("no literal search for '" + value + "' on " + attrName + " received, filters were: " + filters, found);
    }

    private static boolean containsLiteralSubstring(Filter filter, String attrName, String value)
    {
        switch (filter.getFilterType())
        {
        case Filter.FILTER_TYPE_AND:
        case Filter.FILTER_TYPE_OR:
        {
            Filter[] components = filter.getComponents();
            for (int i = 0; i != components.length; i++)
            {
                if (containsLiteralSubstring(components[i], attrName, value))
                {
                    return true;
                }
            }
            return false;
        }
        case Filter.FILTER_TYPE_NOT:
            return containsLiteralSubstring(filter.getNOTComponent(), attrName, value);
        case Filter.FILTER_TYPE_SUBSTRING:
        {
            String[] any = filter.getSubAnyStrings();
            return attrName.equalsIgnoreCase(filter.getAttributeName())
                && filter.getSubInitialString() == null
                && filter.getSubFinalString() == null
                && any.length == 1
                && value.equals(any[0]);
        }
        default:
            return false;
        }
    }

    /*
     * Any leaf assertion carrying a fragment of the attacker value, other than the single literal
     * "*value*" substring assertion, was produced by the value rewriting the filter structure.
     */
    private static void checkNoInjectedComponent(Filter filter, String value)
    {
        switch (filter.getFilterType())
        {
        case Filter.FILTER_TYPE_AND:
        case Filter.FILTER_TYPE_OR:
        {
            Filter[] components = filter.getComponents();
            for (int i = 0; i != components.length; i++)
            {
                checkNoInjectedComponent(components[i], value);
            }
            return;
        }
        case Filter.FILTER_TYPE_NOT:
            checkNoInjectedComponent(filter.getNOTComponent(), value);
            return;
        case Filter.FILTER_TYPE_SUBSTRING:
        {
            List<String> parts = new ArrayList<String>();
            if (filter.getSubInitialString() != null)
            {
                parts.add(filter.getSubInitialString());
            }
            String[] any = filter.getSubAnyStrings();
            for (int i = 0; i != any.length; i++)
            {
                parts.add(any[i]);
            }
            if (filter.getSubFinalString() != null)
            {
                parts.add(filter.getSubFinalString());
            }
            if (parts.size() == 1 && value.equals(parts.get(0)))
            {
                return;
            }
            for (int i = 0; i != parts.size(); i++)
            {
                String part = (String)parts.get(i);
                if (part.length() > 0 && value.indexOf(part) >= 0 && !value.equals(part))
                {
                    fail("value split into filter components: " + filter);
                }
            }
            return;
        }
        case Filter.FILTER_TYPE_EQUALITY:
        case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
        case Filter.FILTER_TYPE_LESS_OR_EQUAL:
        {
            String assertion = filter.getAssertionValue();
            if (assertion != null && assertion.length() > 0 && value.indexOf(assertion) >= 0)
            {
                fail("injected filter component: " + filter);
            }
            return;
        }
        default:
            return;
        }
    }

    static class FilterRecorder
        extends InMemoryOperationInterceptor
    {
        private final List<Filter> filters = new ArrayList<Filter>();

        public void processSearchRequest(InMemoryInterceptedSearchRequest request)
        {
            synchronized (filters)
            {
                filters.add(request.getRequest().getFilter());
            }
        }

        List<Filter> getFilters()
        {
            synchronized (filters)
            {
                return new ArrayList<Filter>(filters);
            }
        }
    }
}
