
static char const rcsid[] =
    "$Id: easy-tls.c,v 1.4 2002/03/05 09:07:16 bodo Exp $";

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#ifndef NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#if OPENSSL_VERSION_NUMBER < 0x00904000L /* 0.9.4-dev */
# error "This program needs OpenSSL 0.9.4 or later."
#endif

#include "easy-tls.h"           /* include after <openssl/ssl.h> if both are
                                 * needed */

#if TLS_INFO_SIZE > PIPE_BUF
# if PIPE_BUF < 512
#  error "PIPE_BUF < 512"       /* non-POSIX */
# endif
# error "TLS_INFO_SIZE > PIPE_BUF"
#endif

/*****************************************************************************/

#ifdef TLS_APP
# include TLS_APP
#endif

/*-
 * Applications can define:
 *   TLS_APP_PROCESS_INIT -- void ...(int fd, int client_p, void *apparg)
 *   TLS_CUMULATE_ERRORS
 *   TLS_ERROR_BUFSIZ
 *   TLS_APP_ERRFLUSH -- void ...(int child_p, char *, size_t, void *apparg)
 */

#ifndef TLS_APP_PROCESS_INIT
# define TLS_APP_PROCESS_INIT(fd, client_p, apparg) ((void) 0)
#endif

#ifndef TLS_ERROR_BUFSIZ
# define TLS_ERROR_BUFSIZ (10*160)
#endif
#if TLS_ERROR_BUFSIZ < 2        /* {'\n',0} */
# error "TLS_ERROR_BUFSIZE is too small."
#endif

#ifndef TLS_APP_ERRFLUSH
# define TLS_APP_ERRFLUSH tls_app_errflush
static void
tls_app_errflush(int child_p, char *errbuf, size_t num, void *apparg)
{
    fputs(errbuf, stderr);
}
#endif

/*****************************************************************************/

#ifdef DEBUG_TLS
# define DEBUG_MSG(x) fprintf(stderr,"  %s\n",x)
# define DEBUG_MSG2(x,y) fprintf(stderr, "  %s: %d\n",x,y)
static int tls_loop_count = 0;
static int tls_select_count = 0;
#else
# define DEBUG_MSG(x) (void)0
# define DEBUG_MSG2(x,y) (void)0
#endif

static void tls_rand_seed_uniquely(void);
static void tls_proxy(int clear_fd, int tls_fd, int info_fd, SSL_CTX *ctx,
                      int client_p);
static int tls_socket_nonblocking(int fd);
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
void print_cn_name(const char* label, X509_NAME* const name);
void print_san_name(const char* label, X509* const cert);

static int tls_child_p = 0;
static void *tls_child_apparg;

struct tls_start_proxy_args tls_start_proxy_defaultargs(void)
{
    struct tls_start_proxy_args ret;

    ret.fd = -1;
    ret.client_p = -1;
    ret.ctx = NULL;
    ret.pid = NULL;
    ret.infofd = NULL;

    return ret;
}

/*-
 * Slice in TLS proxy process at fd.
 * Return value:
 *   0    ok  (*pid is set to child's PID if pid != NULL),
 *   < 0  look at errno
 *   > 0  other error
 *   (return value encodes place of error)
 *
 */
int tls_start_proxy(struct tls_start_proxy_args a, void *apparg)
{
    int fds[2] = { -1, -1 };
    int infofds[2] = { -1, -1 };
    int r, getfd, getfl;
    int ret;

    DEBUG_MSG2("tls_start_proxy fd", a.fd);
    DEBUG_MSG2("tls_start_proxy client_p", a.client_p);

    if (a.fd == -1 || a.client_p == -1 || a.ctx == NULL)
        return 1;

    if (a.pid != NULL) {
        *a.pid = 0;
    }
    if (a.infofd != NULL) {
        *a.infofd = -1;
    }

    r = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (r == -1)
        return -1;
    if (a.fd >= FD_SETSIZE || fds[0] >= FD_SETSIZE) {
        ret = 2;
        goto err;
    }
    if (a.infofd != NULL) {
        r = pipe(infofds);
        if (r == -1) {
            ret = -3;
            goto err;
        }
    }

//vne:: do not fork in case of client 
#if 0
    if(a.client_p == 1)
    {
        DEBUG_MSG("VNE:::: NOT FORKING>>>> ");
        r = 0;
    }   
    else 
    {
        r = fork();
    }
#else 
     r = fork();

#endif 
    if (r == -1) {
        ret = -4;
        goto err;
    }
    if (r == 0) {
        DEBUG_MSG("fork");
        tls_child_p = 1;
        tls_child_apparg = apparg;
        close(fds[1]);
        if (infofds[0] != -1)
            close(infofds[0]);
        TLS_APP_PROCESS_INIT(a.fd, a.client_p, apparg);
        DEBUG_MSG("TLS_APP_PROCESS_INIT");
        tls_proxy(fds[0], a.fd, infofds[1], a.ctx, a.client_p);
        exit(0);
    }
    if (a.pid != NULL)
        *a.pid = r;
    if (infofds[1] != -1) {
        close(infofds[1]);
        infofds[1] = -1;
    }
    /* install fds[1] in place of fd: */
    close(fds[0]);
    fds[0] = -1;
    getfd = fcntl(a.fd, F_GETFD);
    getfl = fcntl(a.fd, F_GETFL);
    r = dup2(fds[1], a.fd);
    close(fds[1]);
    fds[1] = -1;
    if (r == -1) {
        ret = -5;
        goto err;
    }
    if (getfd != 1)
        fcntl(a.fd, F_SETFD, getfd);
    if (getfl & O_NONBLOCK)
        (void)tls_socket_nonblocking(a.fd);
    if (a.infofd != NULL)
        *a.infofd = infofds[0];
    return 0;

 err:
    if (fds[0] != -1)
        close(fds[0]);
    if (fds[1] != -1)
        close(fds[1]);
    if (infofds[0] != -1)
        close(infofds[0]);
    if (infofds[1] != -1)
        close(infofds[1]);
    return ret;
}

/*****************************************************************************/

static char errbuf[TLS_ERROR_BUFSIZ];
static size_t errbuf_i = 0;

static void tls_errflush(void *apparg)
{
    if (errbuf_i == 0)
        return;

    assert(errbuf_i < sizeof(errbuf));
    assert(errbuf[errbuf_i] == 0);
    if (errbuf_i == sizeof(errbuf) - 1) {
        /* make sure we have a newline, even if string has been truncated */
        errbuf[errbuf_i - 1] = '\n';
    }

    /*
     * TLS_APP_ERRFLUSH may modify the string as needed, e.g. substitute
     * other characters for \n for convenience
     */
    TLS_APP_ERRFLUSH(tls_child_p, errbuf, errbuf_i, apparg);

    errbuf_i = 0;
}

static void tls_errprintf(int flush, void *apparg, const char *fmt, ...)
{
    va_list args;
    int r;

    if (errbuf_i < sizeof(errbuf) - 1) {
        size_t n;

        va_start(args, fmt);
        n = (sizeof(errbuf)) - errbuf_i;
        r = vsnprintf(errbuf + errbuf_i, n, fmt, args);
        va_end(args);
        if (r >= n)
            r = n - 1;
        if (r >= 0) {
            errbuf_i += r;
        } else {
            errbuf_i = sizeof(errbuf) - 1;
            errbuf[errbuf_i] = '\0';
        }
        assert(errbuf_i < sizeof(errbuf));
        assert(errbuf[errbuf_i] == 0);
    }
#ifndef TLS_CUMULATE_ERRORS
    tls_errflush(apparg);
#else
    if (flush)
        tls_errflush(apparg);
#endif
}

/*
 * app_prefix.. are for additional information provided by caller. If OpenSSL
 * error queue is empty, print default_text ("???" if NULL).
 */
static char *tls_openssl_errors(const char *app_prefix_1,
                                const char *app_prefix_2,
                                const char *default_text, void *apparg)
{
    static char reasons[255];
    size_t reasons_i;
    unsigned long err;
    const char *file;
    int line;
    const char *data;
    int flags;
    char *errstring;
    int printed_something = 0;

    reasons_i = 0;

    assert(app_prefix_1 != NULL);
    assert(app_prefix_2 != NULL);

    if (default_text == NULL)
        default_text = "?" "?" "?";

    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        if (reasons_i < sizeof(reasons)) {
            size_t n;
            int r;

            n = (sizeof(reasons)) - reasons_i;
            r = snprintf(reasons + reasons_i, n, "%s%s",
                         (reasons_i > 0 ? ", " : ""),
                         ERR_reason_error_string(err));
            if (r >= n)
                r = n - 1;
            if (r >= 0) {
                reasons_i += r;
            } else {
                reasons_i = sizeof(reasons);
            }
            assert(reasons_i <= sizeof(reasons));
        }

        errstring = ERR_error_string(err, NULL);
        assert(errstring != NULL);
        tls_errprintf(0, apparg, "OpenSSL error%s%s: %s:%s:%d:%s\n",
                      app_prefix_1, app_prefix_2, errstring, file, line,
                      (flags & ERR_TXT_STRING) ? data : "");
        printed_something = 1;
    }

    if (!printed_something) {
        assert(reasons_i == 0);
        snprintf(reasons, sizeof(reasons), "%s", default_text);
        tls_errprintf(0, apparg, "OpenSSL error%s%s: %s\n", app_prefix_1,
                      app_prefix_2, default_text);
    }
#ifdef TLS_CUMULATE_ERRORS
    tls_errflush(apparg);
#endif
    assert(errbuf_i == 0);

    return reasons;
}

/*****************************************************************************/

static int tls_init_done = 0;

static int tls_init(void *apparg)
{
    DEBUG_MSG("vne:: tls_init ");
    if (tls_init_done)
        return 0;

    SSL_load_error_strings();
    if (!SSL_library_init() /* aka SSLeay_add_ssl_algorithms() */ ) {
        tls_errprintf(1, apparg, "SSL_library_init failed.\n");
        return -1;
    }
    tls_init_done = 1;
    tls_rand_seed();
    return 0;
}

/*****************************************************************************/

static void tls_rand_seed_uniquely(void)
{
    struct {
        pid_t pid;
        time_t time;
        void *stack;
    } data;

    data.pid = getpid();
    data.time = time(NULL);
    data.stack = (void *)&data;

    RAND_seed((const void *)&data, sizeof(data));
}

void tls_rand_seed(void)
{
    struct {
        struct utsname uname;
        int uname_1;
        int uname_2;
        uid_t uid;
        uid_t euid;
        gid_t gid;
        gid_t egid;
    } data;

    data.uname_1 = uname(&data.uname);
    data.uname_2 = errno;       /* Let's hope that uname fails randomly :-) */

    data.uid = getuid();
    data.euid = geteuid();
    data.gid = getgid();
    data.egid = getegid();

    RAND_seed((const void *)&data, sizeof(data));
    tls_rand_seed_uniquely();
}

static int tls_rand_seeded_p = 0;

#define my_MIN_SEED_BYTES 256   /* struct stat can be larger than 128 */
int tls_rand_seed_from_file(const char *filename, size_t n, void *apparg)
{
    /*
     * Seed OpenSSL's random number generator from file. Try to read n bytes
     * if n > 0, whole file if n == 0.
     */

    int r;

    if (tls_init(apparg) == -1)
        return -1;
    tls_rand_seed();

    r = RAND_load_file(filename,
                       (n > 0 && n < LONG_MAX) ? (long)n : LONG_MAX);
    /*
     * r is the number of bytes filled into the random number generator,
     * which are taken from "stat(filename, ...)" in addition to the file
     * contents.
     */
    assert(1 < my_MIN_SEED_BYTES);
    /*
     * We need to detect at least those cases when the file does not exist at
     * all.  With current versions of OpenSSL, this should do it:
     */
    if (n == 0)
        n = my_MIN_SEED_BYTES;
    if (r < n) {
        tls_errprintf(1, apparg,
                      "rand_seed_from_file: could not read %d bytes from %s.\n",
                      n, filename);
        return -1;
    } else {
        tls_rand_seeded_p = 1;
        return 0;
    }
}

void tls_rand_seed_from_memory(const void *buf, size_t n)
{
    size_t i = 0;

    while (i < n) {
        size_t rest = n - i;
        int chunk = rest < INT_MAX ? (int)rest : INT_MAX;
        RAND_seed((const char *)buf + i, chunk);
        i += chunk;
    }
    tls_rand_seeded_p = 1;
}

/*****************************************************************************/

struct tls_x509_name_string {
    char str[100];
};

static void
tls_get_x509_subject_name_oneline(X509 *cert,
                                  struct tls_x509_name_string *namestring)
{
    X509_NAME *name;

    if (cert == NULL) {
        namestring->str[0] = '\0';
        return;
    }

    name = X509_get_subject_name(cert); /* does not increment any reference
                                         * counter */

    assert(sizeof(namestring->str) >= 4); /* "?" or "...", plus 0 */

    if (name == NULL) {
        namestring->str[0] = '?';
        namestring->str[1] = 0;
    } else {
        size_t len;

        X509_NAME_oneline(name, namestring->str, sizeof(namestring->str));
        len = strlen(namestring->str);
        assert(namestring->str[len] == 0);
        assert(len < sizeof(namestring->str));

        if (len + 1 == sizeof(namestring->str)) {
            /*
             * (Probably something was cut off.) Does not really work --
             * X509_NAME_oneline truncates after name components, we cannot
             * tell from the result whether anything is missing.
             */

            assert(namestring->str[len] == 0);
            namestring->str[--len] = '.';
            namestring->str[--len] = '.';
            namestring->str[--len] = '.';
        }
    }
}

/*****************************************************************************/

/* to hinder OpenSSL from asking for passphrases */
static int no_passphrase_callback(char *buf, int num, int w, void *arg)
{
    return -1;
}

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
static int verify_dont_fail_cb(X509_STORE_CTX *c, void *unused_arg)
#else
static int verify_dont_fail_cb(X509_STORE_CTX *c)
#endif
{
    int i;

    i = X509_verify_cert(c);    /* sets c->error */
    DEBUG_MSG2("vne:: callback ", i);
    DEBUG_MSG2("vne:: openssl no ", OPENSSL_VERSION_NUMBER);
#if OPENSSL_VERSION_NUMBER >= 0x00905000L /* don't allow unverified
                                           * certificates -- they could
                                           * survive session reuse, but
                                           * OpenSSL < 0.9.5-dev does not
                                           * preserve their verify_result */
    if (i == 0)
        return 1;
    else
#endif
        return i;
}

static DH *tls_dhe1024 = NULL;  /* generating these takes a while, so do it
                                 * just once */

void tls_set_dhe1024(int i, void *apparg)
{
    DSA *dsaparams;
    DH *dhparams;
    const char *seed[] = { ";-)  :-(  :-)  :-(  ",
        ";-)  :-(  :-)  :-(  ",
        "Random String no. 12",
        ";-)  :-(  :-)  :-(  ",
        "hackers have even mo", /* from jargon file */
    };
    unsigned char seedbuf[20];

    tls_init(apparg);
    if (i >= 0) {
        i %= sizeof(seed) / sizeof(seed[0]);
        assert(strlen(seed[i]) == 20);
        memcpy(seedbuf, seed[i], 20);
        dsaparams =
            DSA_generate_parameters(1024, seedbuf, 20, NULL, NULL, 0, NULL);
    } else {
        /* random parameters (may take a while) */
        dsaparams =
            DSA_generate_parameters(1024, NULL, 0, NULL, NULL, 0, NULL);
    }

    if (dsaparams == NULL) {
        tls_openssl_errors("", "", NULL, apparg);
        return;
    }
    dhparams = DSA_dup_DH(dsaparams);
    DSA_free(dsaparams);
    if (dhparams == NULL) {
        tls_openssl_errors("", "", NULL, apparg);
        return;
    }
    if (tls_dhe1024 != NULL)
        DH_free(tls_dhe1024);
    tls_dhe1024 = dhparams;
}

struct tls_create_ctx_args tls_create_ctx_defaultargs(void)
{
    struct tls_create_ctx_args ret;

    ret.client_p = 0;
    ret.certificate_file = NULL;
    ret.key_file = NULL;
    ret.ca_file = NULL;
    ret.crl_file = NULL;
    ret.verify_depth = -1;
    ret.fail_unless_verified = 0;
    ret.export_p = 0;

    return ret;
}

SSL_CTX *tls_create_ctx(struct tls_create_ctx_args a, void *apparg)
{
    int r;
    static long context_num = 0;
    SSL_CTX *ret;
    const char *err_pref_1 = "", *err_pref_2 = "";

    DEBUG_MSG("vne:: tls_create_ctx ");
    if (tls_init(apparg) == -1)
        return NULL;

    ret =
        SSL_CTX_new((a.client_p ? SSLv23_client_method :
                     SSLv23_server_method) ());

    if (ret == NULL)
        goto err;

    SSL_CTX_set_default_passwd_cb(ret, no_passphrase_callback);
    SSL_CTX_set_mode(ret, SSL_MODE_ENABLE_PARTIAL_WRITE);

    if (!a.client_p && ((a.certificate_file != NULL) || (a.key_file != NULL))) {
        if (a.key_file == NULL) {
            tls_errprintf(1, apparg, "Need a key file.\n");
            goto err_return;
        }
        if (a.certificate_file == NULL) {
            tls_errprintf(1, apparg, "Need a certificate chain file.\n");
            goto err_return;
        }

        if (!SSL_CTX_use_PrivateKey_file(ret, a.key_file, SSL_FILETYPE_PEM))
            goto err;
        if (!tls_rand_seeded_p) {
            /*
             * particularly paranoid people may not like this -- so provide
             * your own random seeding before calling this
             */
            if (tls_rand_seed_from_file(a.key_file, 0, apparg) == -1)
                goto err_return;
        }
        if (!SSL_CTX_use_certificate_chain_file(ret, a.certificate_file))
            goto err;
        if (!SSL_CTX_check_private_key(ret)) {
            tls_errprintf(1, apparg,
                          "Private key \"%s\" does not match certificate \"%s\".\n",
                          a.key_file, a.certificate_file);
            goto err_peek;
        }
    }

    if ((a.ca_file != NULL) || (a.verify_depth >= 0)) {
        context_num++;
        r = SSL_CTX_set_session_id_context(ret, (const void *)&context_num,
                                           (unsigned int)sizeof(context_num));
        if (!r)
            goto err;

        if(a.client_p) {
           SSL_CTX_set_verify(ret, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
        }
#if 0//vne::
        SSL_CTX_set_verify(ret,
                           SSL_VERIFY_PEER | (a.fail_unless_verified ?
                                              SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                                              : 0), 0);
        if (!a.fail_unless_verified)
	{
           SSL_CTX_set_cert_verify_callback(ret, verify_dont_fail_cb, NULL);
        }
#endif 

        if (a.verify_depth >= 0 && a.client_p == 1)
	{
	   DEBUG_MSG2("vne:: setting verify depth", a.verify_depth);
           SSL_CTX_set_verify_depth(ret, a.verify_depth);
        }

        if (a.ca_file != NULL) {
            /* does not report failure if file does not exist ... */
            /* NULL argument means no CA-directory */
            r = SSL_CTX_load_verify_locations(ret, a.ca_file, NULL);
            if (!r) {
                err_pref_1 = " while processing certificate file ";
                err_pref_2 = a.ca_file;
                goto err;
            }
#if 1
           // set crls 
           if(a.crl_file != NULL && a.client_p == 1)
           {
              X509_STORE *x509_ctx = SSL_CTX_get_cert_store(ret);
              X509_LOOKUP *lookup = NULL;
	      X509_STORE_set_flags(x509_ctx, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	      //X509_STORE_set_flags(x509_ctx, X509_V_FLAG_CRL_CHECK);
              //read the crl file
              //
	      DEBUG_MSG2("vne:: setting crl flags", a.crl_file);
              if (!(lookup = X509_STORE_add_lookup(x509_ctx, X509_LOOKUP_file())) ||
		    (X509_load_crl_file(lookup, a.crl_file, X509_FILETYPE_PEM) != 1)) {
			//fprintf(stderr, "Failed X509 crl init for %s\n", CERTNAME);
			goto err;
		}
           } 

#endif 
         if (!a.client_p) {
                /*
                 * SSL_load_client_CA_file is a misnomer, it just creates a
                 * list of CNs.
                 */
                SSL_CTX_set_client_CA_list(ret,
                                           SSL_load_client_CA_file
                                           (a.ca_file));
                /*
                 * SSL_CTX_set_client_CA_list does not have a return value;
                 * it does not really need one, but make sure (we really test
                 * if SSL_load_client_CA_file worked)
                 */
                if (SSL_CTX_get_client_CA_list(ret) == NULL) {
                    tls_errprintf(1, apparg,
                                  "Could not set client CA list from \"%s\".\n",
                                  a.ca_file);
                    goto err_peek;
                }
            }
        }
    }

    if (!a.client_p) {
        if (tls_dhe1024 == NULL) {
            int i;

            if (RAND_bytes((unsigned char *)&i, sizeof(i)) <= 0)
                goto err_return;
            /*
             * make sure that i is non-negative -- pick one of the provided
             * seeds
             */
            if (i < 0)
                i = -i;
            if (i < 0)
                i = 0;
            tls_set_dhe1024(i, apparg);
            if (tls_dhe1024 == NULL)
                goto err_return;
        }

        if (!SSL_CTX_set_tmp_dh(ret, tls_dhe1024))
            goto err;

        /* avoid small subgroup attacks: */
        SSL_CTX_set_options(ret, SSL_OP_SINGLE_DH_USE);
    }
#ifndef NO_RSA
    if (!a.client_p && a.export_p) {
        RSA *tmpkey;

        tmpkey = RSA_generate_key(512, RSA_F4, 0, NULL);
        if (tmpkey == NULL)
            goto err;
        if (!SSL_CTX_set_tmp_rsa(ret, tmpkey)) {
            RSA_free(tmpkey);
            goto err;
        }
        RSA_free(tmpkey);       /* SSL_CTX_set_tmp_rsa uses a duplicate. */
    }
#endif

    return ret;

 err_peek:
    if (!ERR_peek_error())
        goto err_return;
 err:
    tls_openssl_errors(err_pref_1, err_pref_2, NULL, apparg);
 err_return:
    if (ret != NULL)
        SSL_CTX_free(ret);
    return NULL;
}

/*****************************************************************************/

void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;
    
    do
    {
        if(!cert) break; /* failed */
        
        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;
        
        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */
        
        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;
                
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                
                if(len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }
                
                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }
                
                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);
    
    if(names)
        GENERAL_NAMES_free(names);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
    
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{

    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
#if 0 
    X509* pub_cert = SSL_CTX_get0_certificate(x509_ctx);
    X509_NAME* piname = cert ? X509_get_issuer_name(pub_cert) : NULL;
    X509_NAME* psname = cert ? X509_get_subject_name(pub_cert) : NULL;

    /* Issuer is the authority we trust that warrants nothing useful */
    print_cn_name("Pub Issuer (cn)", piname);
    
    /* Subject is who the certificate is issued to by the authority  */
    print_cn_name("Pub Subject (cn)", psname);
#endif

    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    
    /* Issuer is the authority we trust that warrants nothing useful */
    print_cn_name("Issuer (cn)", iname);
    
    /* Subject is who the certificate is issued to by the authority  */
    print_cn_name("Subject (cn)", sname);
    
    if (preverify != 1)
    {
       fprintf(stdout, "initial val failed: preverify=%d)\n", preverify);
        return preverify;
    }
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs */
        print_san_name("Subject (san)", cert);
        X509_OBJECT robj;
        int rval = X509_STORE_get_by_subject(x509_ctx, X509_LU_X509, sname, &robj);
        fprintf(stdout, "vne:: get by sub %d\n", rval);
        if(rval == 0) {
          preverify = 0;
          X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REJECTED);
        }
    }

#if 0 
    if(preverify == 0)
    {
        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = 509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if(err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if(err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }
#endif

    return preverify;
}

static int tls_socket_nonblocking(int fd)
{
    int v, r;

    v = fcntl(fd, F_GETFL, 0);
    if (v == -1) {
        if (errno == EINVAL)
            return 0;           /* already shut down -- ignore */
        return -1;
    }
    r = fcntl(fd, F_SETFL, v | O_NONBLOCK);
    if (r == -1) {
        if (errno == EINVAL)
            return 0;           /* already shut down -- ignore */
        return -1;
    }
    return 0;
}

static int max(int a, int b)
{
    return a > b ? a : b;
}

/* timeout, -1 means no timeout */
static void
tls_sockets_select(int read_select_1, int read_select_2, int write_select_1,
                   int write_select_2, int seconds)
{
    int maxfd, n;
    fd_set reads, writes;
    struct timeval timeout;
    struct timeval *timeout_p;

    assert(read_select_1 >= -1 && read_select_2 >= -1 && write_select_1 >= -1
           && write_select_2 >= -1);
    assert(read_select_1 < FD_SETSIZE && read_select_2 < FD_SETSIZE - 1
           && write_select_1 < FD_SETSIZE - 1
           && write_select_2 < FD_SETSIZE - 1);

    maxfd =
        max(max(read_select_1, read_select_2),
            max(write_select_1, write_select_2));
    assert(maxfd >= 0);

    FD_ZERO(&reads);
    FD_ZERO(&writes);

    for (n = 0; n < 4; ++n) {
        int i = n % 2;
        int w = n >= 2;
        /* loop over all (i, w) in {0,1}x{0,1} */
        int fd;

        if (i == 0 && w == 0)
            fd = read_select_1;
        else if (i == 1 && w == 0)
            fd = read_select_2;
        else if (i == 0 && w == 1)
            fd = write_select_1;
        else {
            assert(i == 1 && w == 1);
            fd = write_select_2;
        }

        if (fd >= 0) {
            if (w == 0)
                FD_SET(fd, &reads);
            else                /* w == 1 */
                FD_SET(fd, &writes);
        }
    }

    if (seconds >= 0) {
        timeout.tv_sec = seconds;
        timeout.tv_usec = 0;
        timeout_p = &timeout;
    } else
        timeout_p = NULL;

    DEBUG_MSG2("select no.", ++tls_select_count);
    select(maxfd + 1, &reads, &writes, (fd_set *) NULL, timeout_p);
    DEBUG_MSG("cont.");
}

/*****************************************************************************/

#define TUNNELBUFSIZE (16*1024)
struct tunnelbuf {
    char buf[TUNNELBUFSIZE];
    size_t len;
    size_t offset;
};

static int tls_connect_attempt(SSL *, int *write_select, int *read_select,
                               int *closed, int *progress,
                               const char **err_pref);

static int tls_accept_attempt(SSL *, int *write_select, int *read_select,
                              int *closed, int *progress,
                              const char **err_pref);

static int tls_write_attempt(SSL *, struct tunnelbuf *, int *write_select,
                             int *read_select, int *closed, int *progress,
                             const char **err_pref);

static int tls_read_attempt(SSL *, struct tunnelbuf *, int *write_select,
                            int *read_select, int *closed, int *progress,
                            const char **err_pref);

static int write_attempt(int fd, struct tunnelbuf *, int *select, int *closed,
                         int *progress);

static int read_attempt(int fd, struct tunnelbuf *, int *select, int *closed,
                        int *progress);

static void write_info(SSL *ssl, int *info_fd)
{
    if (*info_fd != -1) {
        long v;
        int v_ok;
        struct tls_x509_name_string peer;
        char infobuf[TLS_INFO_SIZE];
        int r;

        DEBUG_MSG("write_info");
        v = SSL_get_verify_result(ssl);
        v_ok = (v == X509_V_OK) ? 'A' : 'E'; /* Auth./Error */
        {
            X509 *peercert;

            peercert = SSL_get_peer_certificate(ssl);
            tls_get_x509_subject_name_oneline(peercert, &peer);
            if (peercert != NULL)
                X509_free(peercert);
        }
        if (peer.str[0] == '\0')
            v_ok = '0';         /* no cert at all */
        else if (strchr(peer.str, '\n')) {
            /* should not happen, but make sure */
            *strchr(peer.str, '\n') = '\0';
        }
        r = snprintf(infobuf, sizeof(infobuf), "%c:%s\n%s\n", v_ok,
                     X509_verify_cert_error_string(v), peer.str);
        DEBUG_MSG2("snprintf", r);
        if (r == -1 || r >= sizeof(infobuf))
            r = sizeof(infobuf) - 1;
        write(*info_fd, infobuf, r);
        close(*info_fd);
        *info_fd = -1;
    }
}

/* tls_proxy expects that all fds are closed after return */
static void
tls_proxy(int clear_fd, int tls_fd, int info_fd, SSL_CTX *ctx, int client_p)
{
    struct tunnelbuf clear_to_tls, tls_to_clear;
    SSL *ssl;
    BIO *rbio, *wbio;
    int closed, in_handshake;
    const char *err_pref_1 = "", *err_pref_2 = "";
    const char *err_def = NULL;

    assert(clear_fd != -1);
    assert(tls_fd != -1);
    assert(clear_fd < FD_SETSIZE);
    assert(tls_fd < FD_SETSIZE);
    /* info_fd may be -1 */
    assert(ctx != NULL);

    tls_rand_seed_uniquely();

    tls_socket_nonblocking(clear_fd);
    DEBUG_MSG2("clear_fd", clear_fd);
    tls_socket_nonblocking(tls_fd);
    DEBUG_MSG2("tls_fd", tls_fd);

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto err;
    DEBUG_MSG("SSL_new");
    if (!SSL_set_fd(ssl, tls_fd))
        goto err;
    rbio = SSL_get_rbio(ssl);
    wbio = SSL_get_wbio(ssl);   /* should be the same, but who cares */
    assert(rbio != NULL);
    assert(wbio != NULL);
    if (client_p)
        SSL_set_connect_state(ssl);
    else
        SSL_set_accept_state(ssl);

    closed = 0;
    in_handshake = 1;
    tls_to_clear.len = 0;
    tls_to_clear.offset = 0;
    clear_to_tls.len = 0;
    clear_to_tls.offset = 0;

    err_def = "I/O error";

    /*
     * loop finishes as soon as we detect that one side closed; when all
     * (program and OS) buffers have enough space, the data from the last
     * succesful read in each direction is transferred before close
     */
    do {
        int clear_read_select = 0, clear_write_select = 0,
            tls_read_select = 0, tls_write_select = 0, progress = 0;
        int r;
        unsigned long num_read = BIO_number_read(rbio),
            num_written = BIO_number_written(wbio);

        DEBUG_MSG2("loop iteration", ++tls_loop_count);

        if (in_handshake) {
            DEBUG_MSG("in_handshake");
            if (client_p)
                r = tls_connect_attempt(ssl, &tls_write_select,
                                        &tls_read_select, &closed, &progress,
                                        &err_pref_1);
            else
                r = tls_accept_attempt(ssl, &tls_write_select,
                                       &tls_read_select, &closed, &progress,
                                       &err_pref_1);
            if (r != 0) {
                write_info(ssl, &info_fd);
                goto err;
            }
            if (closed)
                goto err_return;
            if (!SSL_in_init(ssl)) {
                in_handshake = 0;
                write_info(ssl, &info_fd);
            }
        }

        if (clear_to_tls.len != 0 && !in_handshake) {
            assert(!closed);

            r = tls_write_attempt(ssl, &clear_to_tls, &tls_write_select,
                                  &tls_read_select, &closed, &progress,
                                  &err_pref_1);
            if (r != 0)
                goto err;
            if (closed) {
                assert(progress);
                tls_to_clear.offset = 0;
                tls_to_clear.len = 0;
            }
        }

        if (tls_to_clear.len != 0) {
            assert(!closed);

            r = write_attempt(clear_fd, &tls_to_clear, &clear_write_select,
                              &closed, &progress);
            if (r != 0)
                goto err_return;
            if (closed) {
                assert(progress);
                clear_to_tls.offset = 0;
                clear_to_tls.len = 0;
            }
        }

        if (!closed) {
            if (clear_to_tls.offset + clear_to_tls.len <
                sizeof(clear_to_tls.buf)) {
                r = read_attempt(clear_fd, &clear_to_tls, &clear_read_select,
                                 &closed, &progress);
                if (r != 0)
                    goto err_return;
                //if (client_p)    closed = 0;//vne::
                if (closed) {
                    r = SSL_shutdown(ssl);
                    DEBUG_MSG2("SSL_shutdown", r);
                }
            }
        }

        if (!closed && !in_handshake) {
            if (tls_to_clear.offset + tls_to_clear.len <
                sizeof(tls_to_clear.buf)) {
                r = tls_read_attempt(ssl, &tls_to_clear, &tls_write_select,
                                     &tls_read_select, &closed, &progress,
                                     &err_pref_1);
                if (r != 0)
                    goto err;
                if (closed) {
                    r = SSL_shutdown(ssl);
                    DEBUG_MSG2("SSL_shutdown", r);
                }
            }
        }

        if (!progress) {
            DEBUG_MSG("!progress?");
            if (num_read != BIO_number_read(rbio)
                || num_written != BIO_number_written(wbio))
                progress = 1;

            if (!progress) {
                DEBUG_MSG("!progress");
                assert(clear_read_select || tls_read_select
                       || clear_write_select || tls_write_select);
                tls_sockets_select(clear_read_select ? clear_fd : -1,
                                   tls_read_select ? tls_fd : -1,
                                   clear_write_select ? clear_fd : -1,
                                   tls_write_select ? tls_fd : -1, -1);
            }
        }
    } while (!closed);
    return;

 err:
    tls_openssl_errors(err_pref_1, err_pref_2, err_def, tls_child_apparg);
 err_return:
    return;
}

static int
tls_get_error(SSL *ssl, int r, int *write_select, int *read_select,
              int *closed, int *progress)
{
    int err = SSL_get_error(ssl, r);

    if (err == SSL_ERROR_NONE) {
        assert(r > 0);
        *progress = 1;
        return 0;
    }

    assert(r <= 0);

    switch (err) {
    case SSL_ERROR_ZERO_RETURN:
        assert(r == 0);
        *closed = 1;
        *progress = 1;
        return 0;

    case SSL_ERROR_WANT_WRITE:
        *write_select = 1;
        return 0;

    case SSL_ERROR_WANT_READ:
        *read_select = 1;
        return 0;
    }

    return -1;
}

static int
tls_connect_attempt(SSL *ssl, int *write_select, int *read_select,
                    int *closed, int *progress, const char **err_pref)
{
    int n, r;

    DEBUG_MSG("tls_connect_attempt");
    n = SSL_connect(ssl);
    DEBUG_MSG2("SSL_connect", n);
    r = tls_get_error(ssl, n, write_select, read_select, closed, progress);
    if (r == -1)
        *err_pref = " during SSL_connect";

    return r;
}

static int
tls_accept_attempt(SSL *ssl, int *write_select, int *read_select, int *closed,
                   int *progress, const char **err_pref)
{
    int n, r;

    DEBUG_MSG("tls_accept_attempt");
    n = SSL_accept(ssl);
    DEBUG_MSG2("SSL_accept", n);
    r = tls_get_error(ssl, n, write_select, read_select, closed, progress);
    if (r == -1)
        *err_pref = " during SSL_accept";
    return r;
}

static int
tls_write_attempt(SSL *ssl, struct tunnelbuf *buf, int *write_select,
                  int *read_select, int *closed, int *progress,
                  const char **err_pref)
{
    int n, r;

    DEBUG_MSG("tls_write_attempt");
    n = SSL_write(ssl, buf->buf + buf->offset, buf->len);
    DEBUG_MSG2("SSL_write", n);
    r = tls_get_error(ssl, n, write_select, read_select, closed, progress);
    if (n > 0) {
        buf->len -= n;
        assert(buf->len >= 0);
        if (buf->len == 0)
            buf->offset = 0;
        else
            buf->offset += n;
    }
    if (r == -1)
        *err_pref = " during SSL_write";
    return r;
}

static int
tls_read_attempt(SSL *ssl, struct tunnelbuf *buf, int *write_select,
                 int *read_select, int *closed, int *progress,
                 const char **err_pref)
{
    int n, r;
    size_t total;

    DEBUG_MSG("tls_read_attempt");
    total = buf->offset + buf->len;
    assert(total < sizeof(buf->buf));
    n = SSL_read(ssl, buf->buf + total, sizeof(buf->buf) - total);
    DEBUG_MSG2("SSL_read", n);
    r = tls_get_error(ssl, n, write_select, read_select, closed, progress);
    if (n > 0) {
        buf->len += n;
        assert(buf->offset + buf->len <= sizeof(buf->buf));
    }
    if (r == -1)
        *err_pref = " during SSL_read";
    return r;
}

static int get_error(int r, int *select, int *closed, int *progress)
{
    if (r >= 0) {
        *progress = 1;
        if (r == 0)
            *closed = 1;
        return 0;
    } else {
        assert(r == -1);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *select = 1;
            return 0;
        } else if (errno == EPIPE) {
            *progress = 1;
            *closed = 1;
            return 0;
        } else
            return -1;
    }
}

static int write_attempt(int fd, struct tunnelbuf *buf, int *select,
                         int *closed, int *progress)
{
    int n, r;

    DEBUG_MSG("write_attempt");
    n = write(fd, buf->buf + buf->offset, buf->len);
    DEBUG_MSG2("write", n);
    r = get_error(n, select, closed, progress);
    if (n > 0) {
        buf->len -= n;
        assert(buf->len >= 0);
        if (buf->len == 0)
            buf->offset = 0;
        else
            buf->offset += n;
    }
    if (r == -1)
        tls_errprintf(1, tls_child_apparg, "write error: %s\n",
                      strerror(errno));
    return r;
}

static int
read_attempt(int fd, struct tunnelbuf *buf, int *select, int *closed,
             int *progress)
{
    int n, r;
    size_t total;

    DEBUG_MSG("read_attempt");
    total = buf->offset + buf->len;
    assert(total < sizeof(buf->buf));
    n = read(fd, buf->buf + total, sizeof(buf->buf) - total);
    DEBUG_MSG2("read", n);
    r = get_error(n, select, closed, progress);
    if (n > 0) {
        buf->len += n;
        assert(buf->offset + buf->len <= sizeof(buf->buf));
    }
    if (r == -1)
        tls_errprintf(1, tls_child_apparg, "read error: %s\n",
                      strerror(errno));
    return r;
}
