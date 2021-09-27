//wget http://crl3.digicert.com/ssca-ecc-g1.crl
//wget http://curl.haxx.se/ca/cacert.pem
//cat cacert.pem |tr '\n' '%' |sed -e 's/-----END CERTIFICATE-----%%[^%]\+%=\+%-----BEGIN CERTIFICATE-----/-----END CERTIFICATE-----%-----BEGIN CERTIFICATE-----/'  |tr '%' '\n' > cacerts_.pem
//sudo apt-get install libssl-dev
//g++ main.cpp -lcrypto && ./a.out
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
 
using std::cout;
using std::endl;
using std::stringstream;
using std::map;
using std::vector;
using std::string;
 
//----------------------------------------------------------------------
int is_revoked_by_crl(X509 *x509, X509 *issuer, X509_CRL *crl_file)
{
    int is_revoked = -1;
    if (issuer)
    {
        EVP_PKEY *ikey=X509_get_pubkey(issuer);
        ASN1_INTEGER *serial = X509_get_serialNumber(x509);
 
        if (crl_file && ikey && X509_CRL_verify(crl_file, ikey))
        {
            is_revoked = 0;
            STACK_OF(X509_REVOKED) *revoked_list = crl_file->crl->revoked;
            for (int j = 0; j < sk_X509_REVOKED_num(revoked_list) && !is_revoked; j++)
            {
                X509_REVOKED *entry = sk_X509_REVOKED_value(revoked_list, j);
                if (entry->serialNumber->length==serial->length)
                {
                    if (memcmp(entry->serialNumber->data, serial->data, serial->length)==0)
                    {
                        is_revoked=1;
                    }
                }
            }
        }
    }
    return is_revoked;
}
//----------------------------------------------------------------------
int verify_trust(X509 *x509, X509* issuer, X509_CRL *crl_file, const string& cacerts_pem_path)
{
    STACK_OF (X509)* chain = sk_X509_new_null();
    sk_X509_push(chain, issuer);
 
    X509_STORE *store=X509_STORE_new();
    if (store==NULL) { return 0; }
 
    X509_LOOKUP *lookup=X509_STORE_add_lookup(store,X509_LOOKUP_file());
    if (lookup==NULL) { return 0; }
 
    int q1 = X509_LOOKUP_load_file(lookup, cacerts_pem_path.c_str(), X509_FILETYPE_PEM);
    if (!q1) { return 0; }
 
    X509_STORE_CTX *csc = X509_STORE_CTX_new();
    X509_STORE_CTX_init(csc, store, x509, chain);
    X509_STORE_CTX_set_purpose(csc, X509_PURPOSE_SSL_SERVER);
 
    X509_STORE_add_crl(store, crl_file);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
 
    int verify_result=X509_verify_cert(csc);
    if (verify_result!=1)
        cout << "Trust Failure: " << X509_verify_cert_error_string(csc->error) << endl;
 
    X509_STORE_CTX_cleanup(csc);
    X509_STORE_CTX_free(csc);
    X509_STORE_free(store);
    sk_X509_free(chain);
 
    return verify_result;
}
//----------------------------------------------------------------------
vector<string> x509_crl_urls(X509 *x509)
{
    vector<string> list;
    int nid = NID_crl_distribution_points;
    STACK_OF(DIST_POINT) * dist_points =(STACK_OF(DIST_POINT) *)X509_get_ext_d2i(x509, nid, NULL, NULL);
    for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++)
    {
        DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
        DIST_POINT_NAME    *distpoint = dp->distpoint;
        if (distpoint->type==0)//fullname GENERALIZEDNAME
        {
            for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++) 
            {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
                ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
                list.push_back( string( (char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str) ) );
            }
        }
        else if (distpoint->type==1)//relativename X509NAME
        {
            STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
            for (int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++) 
            {
                X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, k);
                ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
                list.push_back( string( (char*)ASN1_STRING_data(d), ASN1_STRING_length(d) ) );
            }
        }
    }
    return list;
}
//----------------------------------------------------------------------
X509 *new_x509(const char* cert_bytes)
{
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, cert_bytes);
    X509 * x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    BIO_free(bio_mem);
    return x509;
}
//----------------------------------------------------------------------
X509_CRL *new_CRL(const char* crl_filename)
{
    BIO *bio = BIO_new_file(crl_filename, "r");
    X509_CRL *crl_file=d2i_X509_CRL_bio(bio,NULL); //if (format == FORMAT_PEM) crl=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
    BIO_free(bio);
    return crl_file;
}
//----------------------------------------------------------------------
int main(int argc, char **argv)
{
    OpenSSL_add_all_algorithms();
    const char cert1_bytes[] = "-----BEGIN CERTIFICATE-----" "\n"
"MIIGrTCCBJWgAwIBAgITHgAAAANP0LqqNA8GRgAAAAAAAzANBgkqhkiG9w0BAQsF" "\n"
"ADAjMSEwHwYDVQQDExhhZGRldi1XSU4tVEZVUTBLR0JVNDktQ0EwHhcNMjEwOTIx" "\n"
"MTAyNDUxWhcNMjIwOTIxMTAzNDUxWjBnMQswCQYDVQQGEwJVUzELMAkGA1UECBMC" "\n"
"Q0ExEDAOBgNVBAoTB0V4dGVycm8xDTALBgNVBAsTBEVuZ2cxKjAoBgNVBAMTIXRl" "\n"
"c3QxLnZuZTEuZW5nZy5hZGRldi5leHRlcnJvLmNvbTCCASIwDQYJKoZIhvcNAQEB" "\n"
"BQADggEPADCCAQoCggEBAKiX8qp2QkozUEBYKES4Cu7Wo2YQFzg4k2qU9rEHn3JJ" "\n"
"wvhi3aVrBkZfGS8VwCDqTrk0+5KdAoGtEQya7G/8758YvJ28gjyc4m2lHO4GpMrc" "\n"
"21qRi0MiB8fpDIGPP+vSrUYIxLoWT13nBYPE/YT1JyUyw3lIGi4mgH7KPW0DwWMh" "\n"
"HoWeI5OnTGjT+KALextDI3ogdSJmFZmdERInTTD6QHcb5tzsxyqJESTwyOkGU/q3" "\n"
"lgwlpaew27MtdcQ+rgTP1hct91GtXOuxr2YLo5MbQtm1OKMK9c01qK/8jdFh8Pq3" "\n"
"Z52yszPzgtG2ktpEyDQubwVWO3KAcRfmv7TBujJIfGUCAwEAAaOCApQwggKQMB0G" "\n"
"A1UdDgQWBBSK75q439o6AWC2VinPVI3H5+U/0zAOBgNVHQ8BAf8EBAMCBSAwHwYD" "\n"
"VR0jBBgwFoAUc9IXewmalau4OlVDKt4O4JKoSPYwRgYDVR0fBD8wPTA7oDmgN4Y1" "\n"
"aHR0cDovLzUyLjcwLjMxLjE4MC9jcmxkL2FkZGV2LVdJTi1URlVRMEtHQlU0OS1D" "\n"
"QS5jcmwwggHmBggrBgEFBQcBAQSCAdgwggHUMIGrBggrBgEFBQcwAoaBnmxkYXA6" "\n"
"Ly8vQ049YWRkZXYtV0lOLVRGVVEwS0dCVTQ5LUNBLENOPUFJQSxDTj1QdWJsaWMl" "\n"
"MjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxEQz1VbmF2YWlsYWJsZUNvbmZp" "\n"
"Z0ROP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9u" "\n"
"QXV0aG9yaXR5MIGPBggrBgEFBQcwAoaBgmh0dHA6Ly9XSU4tVEZVUTBLR0JVNDku" "\n"
"YWRkZXYuYWNjZXNzZGF0YWdyb3VwLm5ldC9DZXJ0RW5yb2xsL1dJTi1URlVRMEtH" "\n"
"QlU0OS5hZGRldi5hY2Nlc3NkYXRhZ3JvdXAubmV0X2FkZGV2LVdJTi1URlVRMEtH" "\n"
"QlU0OS1DQS5jcnQwgZEGCCsGAQUFBzAChoGEZmlsZTovLy8vV0lOLVRGVVEwS0dC" "\n"
"VTQ5LmFkZGV2LmFjY2Vzc2RhdGFncm91cC5uZXQvQ2VydEVucm9sbC9XSU4tVEZV" "\n"
"UTBLR0JVNDkuYWRkZXYuYWNjZXNzZGF0YWdyb3VwLm5ldF9hZGRldi1XSU4tVEZV" "\n"
"UTBLR0JVNDktQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB" "\n"
"AG9fZs1T3gURvCvncbO6vTj782s7IsDnAPF+YYO637dcjp8U/2Zf+qnECEntjAvu" "\n"
"j6eo8Zd8rvsbeuwVnGbbbvL3So2KqjT4vXuSTTGqfipxNNnbqzvFLtjf4vGQbwLX" "\n"
"qW1yg03EvzmqBu1FR8W0+oqcvftj/i8+YiwBoVUXysHh7F6z5wtRHl95AVbgKm0W" "\n"
"IdjHNu0G6lOdazYptrFouacMNulARzXvI3NtPolwZ6mFK6SZDDcTeKNyNnOrM2Gw" "\n"
"TLcZBA96TrgAMN+dKgk9705J/Oys3pOLpd2zh+2TGERKBFbRVAMfnbiTv34ObE9+" "\n"
"na8BGkCT9wA+1gTyZF85ozRhpFtJf5Pi4BF/pmzZGW3ps6pMonq4QOjg+xmK15ic" "\n"
"fe98Q2kgsV/C4UeheeSRisuM2+ndGFlESy/g1IGq5ppXeOtA3bqB9WEzWFdL87CD" "\n"
"BTuWPzeRiqe5CJSHaDi2FTWFac2bwosAv1pBBo87inm+4FKYIVUB46QJq2j8wF5M" "\n"
"1pGRScRdFXFvOdFjaSkX7wWyuatgzoWJsHNe17NZEObgnKMH5TrZ5PmYKyhlmDu0" "\n"
"N2hzycRJyESFp+1QeZGE62qlYHgG20OGALNKhYRoRfjH9NGvlKlKJ2bAwmn1Lwqo" "\n"
"Tv/igwGBzFMAqqtdGzk0vB9uRCaP2473LPruBm92uqL1" "\n"
"-----END CERTIFICATE-----" "\n";
#if 0 
    const char cert1_bytes[] = "-----BEGIN CERTIFICATE-----" "\n"
"MIIDszCCAzigAwIBAgIQDGv40oFewTIKpCtIVTYSOTAKBggqhkjOPQQDAjBMMQsw" "\n"
"CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSYwJAYDVQQDEx1EaWdp" "\n"
"Q2VydCBFQ0MgU2VjdXJlIFNlcnZlciBDQTAeFw0xNTA3MjgwMDAwMDBaFw0xNjA5" "\n"
"MzAxMjAwMDBaMHQxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhJbGxpbm9pczEQMA4G" "\n"
"A1UEBxMHQ2hpY2FnbzEoMCYGA1UEChMfWmFja3MgSW52ZXN0bWVudCBSZXNlYXJj" "\n"
"aCwgSW5jLjEWMBQGA1UEAxMNd3d3LnphY2tzLmNvbTBZMBMGByqGSM49AgEGCCqG" "\n"
"SM49AwEHA0IABOYOkwbEkkL/xKRUFV8xIfXYm5G/CnwpopbjZaLki/buATo2eSNd" "\n"
"0gPYzhzrfpd9HWV34Z/kO/yocvpbOTFrNDijggHSMIIBzjAfBgNVHSMEGDAWgBSj" "\n"
"neYf+do5T8Bu6JHLlaXaMeIKnzAdBgNVHQ4EFgQUtGr+7XN7qK4ZmnEDBNn7V+YI" "\n"
"QU0wIwYDVR0RBBwwGoINd3d3LnphY2tzLmNvbYIJemFja3MuY29tMA4GA1UdDwEB" "\n"
"/wQEAwIDiDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwaQYDVR0fBGIw" "\n"
"YDAuoCygKoYoaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NzY2EtZWNjLWcxLmNy" "\n"
"bDAuoCygKoYoaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NzY2EtZWNjLWcxLmNy" "\n"
"bDBCBgNVHSAEOzA5MDcGCWCGSAGG/WwBATAqMCgGCCsGAQUFBwIBFhxodHRwczov" "\n"
"L3d3dy5kaWdpY2VydC5jb20vQ1BTMHsGCCsGAQUFBwEBBG8wbTAkBggrBgEFBQcw" "\n"
"AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEUGCCsGAQUFBzAChjlodHRwOi8v" "\n"
"Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFQ0NTZWN1cmVTZXJ2ZXJDQS5j" "\n"
"cnQwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNpADBmAjEA2vqnY3CyBs18df3H" "\n"
"h+DJBj8t91Ix6DKdJdrJg/HiPtg9EwQ8TRwZ5Fg4HgTmNaTiAjEAxzYXnrz9tK9N" "\n"
"DEh5AG+tvna+rzsBwEAh/rBPXeFQx2uCt9deviww57Eg4pSx5cBL" "\n"
"-----END CERTIFICATE-----" "\n";
#endif 
 
    const char issuer1_bytes[] = "-----BEGIN CERTIFICATE-----" "\n"
"MIIDrDCCApSgAwIBAgIQCssoukZe5TkIdnRw883GEjANBgkqhkiG9w0BAQwFADBh" "\n"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" "\n"
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD" "\n"
"QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaMEwxCzAJBgNVBAYTAlVT" "\n"
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJjAkBgNVBAMTHURpZ2lDZXJ0IEVDQyBT" "\n"
"ZWN1cmUgU2VydmVyIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ghC6nfYJN6g" "\n"
"LGSkE85AnCNyqQIKDjc/ITa4jVMU9tWRlUvzlgKNcR7E2Munn17voOZ/WpIRllNv" "\n"
"68DLP679Wz9HJOeaBy6Wvqgvu1cYr3GkvXg6HuhbPGtkESvMNCuMo4IBITCCAR0w" "\n"
"EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwNAYIKwYBBQUHAQEE" "\n"
"KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQgYDVR0f" "\n"
"BDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xv" "\n"
"YmFsUm9vdENBLmNybDA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYc" "\n"
"aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAdBgNVHQ4EFgQUo53mH/naOU/A" "\n"
"buiRy5Wl2jHiCp8wHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUwDQYJ" "\n"
"KoZIhvcNAQEMBQADggEBAMeKoENL7HTJxavVHzA1Nm6YVntIrAVjrnuaVyRXzG/6" "\n"
"3qttnMe2uuzO58pzZNvfBDcKAEmzP58mrZGMIOgfiA4q+2Y3yDDo0sIkp0VILeoB" "\n"
"UEoxlBPfjV/aKrtJPGHzecicZpIalir0ezZYoyxBEHQa0+1IttK7igZFcTMQMHp6" "\n"
"mCHdJLnsnLWSB62DxsRq+HfmNb4TDydkskO/g+l3VtsIh5RHFPVfKK+jaEyDj2D3" "\n"
"loB5hWp2Jp2VDCADjT7ueihlZGak2YPqmXTNbk19HOuNssWvFhtOyPNV6og4ETQd" "\n"
"Ea8/B6hPatJ0ES8q/HO3X8IVQwVs1n3aAr0im0/T+Xc=" "\n"
"-----END CERTIFICATE-----" "\n";
 
    //download these files first...
    //wget http://crl3.digicert.com/ssca-ecc-g1.crl
    //wget http://curl.haxx.se/ca/cacert.pem
 
    X509 * x509 = new_x509(cert1_bytes);
    X509 * issuer = new_x509(issuer1_bytes);
    vector<string> crl_urls = x509_crl_urls(x509);
    for(size_t i=0,ix=crl_urls.size(); i<ix; i++)
    {
        cout << crl_urls[i] << endl;
    }
    X509_CRL *crl_file = new_CRL("ssca-ecc-g1.crl");
 
    int is_revoked = is_revoked_by_crl(x509, issuer, crl_file);
    if (is_revoked== 0) cout << "Method 1: Not Revoked" << endl;
    if (is_revoked== 1) cout << "Method 1: Revoked" << endl;
    if (is_revoked==-1) cout << "Method 1: Revocation Unknown" << endl;
 
    int is_trusted = verify_trust(x509, issuer, crl_file, "cacerts.pem");
    if (is_trusted== 1) cout << "Method 2: Trusted" << endl;
    if (is_trusted== 0) cout << "Method 2: Not Trusted" << endl;
    if (is_trusted==-1) cout << "Method 2: Trust Unknown" << endl;
 
    X509_CRL_free(crl_file);
    X509_free(issuer);
    X509_free(x509);
}
//----------------------------------------------------------------------
