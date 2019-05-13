#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef HAVE_DLFCN_H
#  include <dlfcn.h>
#endif
#ifdef HAVE_DL_H
#  include <dl.h>
#endif
#ifdef _WIN32
#  include <windows.h>
#define ssize_t long int
#endif
#include <tcl.h>

#if 10 * TCL_MAJOR_VERSION + TCL_MINOR_VERSION >= 86
/*LISSI*/
/*Здесь какая-то беда, поэтому отказываемся до выяснения причины*/
/*
#  define TCL_INCLUDES_LOADFILE 1
*/
#endif

/* PKCS#11 Definitions for the local platform */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv, func) rv func
#define CK_DECLARE_FUNCTION_POINTER(rv, func) rv (CK_PTR func)
#define CK_CALLBACK_FUNCTION(rv, func) rv (CK_PTR func)
#define CK_NULL_PTR ((void *) 0)

#ifdef _WIN32
#  pragma pack(push, cryptoki, 1)
#endif

#include "pkcs11.h"
/*LISSI*/
#include <pkcs11t_gost.h>
#include "gost_r3411_2012.h"

#ifdef _WIN32
#  pragma pack(pop, cryptoki)
#endif

int wtable[64] = {
  0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021,
  0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
  0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
  0x007F, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
  0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7,
  0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
  0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7,
  0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457};
  
int utf8_to_win1251(const char* text, char* wtext)
{
  int wc, uc;
  int i, j, k, m;
  if (!wtext)
    return 0;
  i=0;
  j=0;
  while (i<strlen(text))
  {
    /* read Unicode character */
    /* read first UTF-8 byte */
    wc = (unsigned char)text[i++];
    /* 11111xxx - not symbol (BOM etc) */
    if (wc>=0xF8) {
      m = -1;
    }
    /* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx -> 0x00010000 — 0x001FFFFF */
    else if (wc>=0xF0) {
      uc = (wc&0x07); 
      m = 3;
    }
    /* 1110xxxx 10xxxxxx 10xxxxxx -> 0x00000800 — 0x0000FFFF */
    else if (wc>=0xE0) {
      uc = (wc&0x0F); 
      m = 2;
    }
    /* 110xxxxx 10xxxxxx -> 0x00000080 — 0x000007FF */
    else if (wc>=0xC0) {
      uc = (wc&0x1F); 
      m = 1;
    }
    /* 0xxxxxxx -> 0x00000000 — 0x0000007F */
    else if (wc<=0x7F) {
      uc = wc;
      m = 0;
    }
    /* 10xxxxxx - data error! */
    else {
      m = -1;
    }
    /* read m UTF-8 bytes (10xxxxxx) */
    k = 1;
    wc = 0;
    while (k<=m && wc<=0xBF)
    {
      wc = (unsigned char)text[i++];
      uc <<= 6;
      uc += (wc&0x3F);
      k++;
    }
    if (wc>0xBF || m<0) {
      uc = -1;
    }
    /* Unicode to Windows-1251 */
    if (uc<0) {
      wc = -1;
    }
    else if (uc<=0x7F) /* ASCII */
    {
      wc = uc;
    }
    else if (uc>=0x0410 && uc<=0x042F) /* А-Я */
    {
      wc = uc - 0x410 + 0xC0;
    }
    else if (uc>=0x0430 && uc<=0x044F) /* а-я */
    {
      wc = uc - 0x0430 + 0xE0;
    }
    else /* Ђ-ї */
    {
      /* search in wtable */
      k = 0;
      while (k<64 && wtable[k]!=uc)
      {
        k++;
      }
      if (k<64)
      {
        wc = k + 0x80;
      }
      else
      {
        wc = '?';
      }
    }
    /* save Windows-1251 character */
    if (wc>0)
    {
      wtext[j++] = (char)wc;
    }
  }
  wtext[j] = 0x00;
  return 1;
}


unsigned char *wrap_for_asn1(unsigned char type, char *prefix, unsigned char *wrap){
    unsigned long length;
    int buflen = 0;
    unsigned char *buf;
    char *format;
    char f0[] = "%02x%02x%s%s";
    char f1[] = "%02x81%02x%s%s";
    char f2[] = "%02x82%04x%s%s";
    char f3[] = "%02x83%06x%s%s";
    char f4[] = "%02x84%08x%s%s";
    length = (unsigned long)(strlen((const char*)wrap) + strlen((const char*)prefix))/2;
    buf = malloc(length + 1 + 2 + length * 2);
    buflen += ( length < 0x80 ? 1:
		length <= 0xff ? 2:
        	length <= 0xffff ? 3:
                length <= 0xffffff ? 4: 5);
    switch (buflen - 1) {
	case 0:
	    format = f0;
	    break;
	case 1:
	    format = f1;
	    break;
	case 2:
	    format = f2;
	    break;
	case 3:
	    format = f3;
	    break;
	case 4:
	    format = f4;
	    break;
    }
    sprintf((char*)buf, (const char *)format, type, length, prefix,wrap);
//    fprintf(stderr, "LENGTH=%lu, BUFLEN=%i\n", length, buflen);
    return (buf);
}

/////////////Parse Certificate///////////////////////////////////
struct asn1_object {
	unsigned long tag;
	unsigned long size;
	void *contents;

	unsigned long asn1rep_len;
	void *asn1rep;
};

struct x509_object {
	struct asn1_object wholething;
		struct asn1_object certificate;
			struct asn1_object version;
			struct asn1_object serial_number;
			struct asn1_object signature_algo;
			struct asn1_object issuer;
			struct asn1_object validity;
			struct asn1_object subject;
			struct asn1_object pubkeyinfo;
				struct asn1_object pubkey_algoid;
					struct asn1_object pubkey_algo;
					struct asn1_object pubkey_algoparm;
				struct asn1_object pubkey;
};

static int _asn1_x509_read_asn1_object(unsigned char *buf, size_t buflen, va_list *args) {
	unsigned char small_object_size;
	unsigned char *buf_p;
	struct asn1_object *outbuf;

	outbuf = va_arg(*args, struct asn1_object *);

	if (outbuf == NULL) {
		return(0);
	}

	if (buflen == 0) {
		return(-1);
	}

	buf_p = buf;

	outbuf->tag = *buf_p;
	buf_p++;
	buflen--;

	/* NULL Tag -- no size is required */
	if (outbuf->tag == 0x00) {
		outbuf->size = 0;
		outbuf->asn1rep_len = 1;
		outbuf->asn1rep = buf;

		return(_asn1_x509_read_asn1_object(buf_p, buflen, args));
	}

	if (buflen == 0) {
		return(-1);
	}

	small_object_size = *buf_p;
	buf_p++;
	buflen--;
	if (buflen == 0) {
		return(-1);
	}

	if ((small_object_size & 0x80) == 0x80) {
		outbuf->size = 0;

		for (small_object_size ^= 0x80; small_object_size; small_object_size--) {
			outbuf->size <<= 8;
			outbuf->size += *buf_p;

			buf_p++;
			buflen--;

			if (buflen == 0) {
				break;
			}
		}
	} else {
		outbuf->size = small_object_size;
	}

	if (outbuf->size > buflen) {
		return(-1);
	}

	if (buflen != 0) {
		outbuf->contents = buf_p;
	}

	outbuf->asn1rep_len = (unsigned long) (outbuf->size + (buf_p - buf));
	outbuf->asn1rep = buf;

	buf_p += outbuf->size;
	buflen -= outbuf->size;

	return(_asn1_x509_read_asn1_object(buf_p, buflen, args));
}

static int asn1_x509_read_asn1_object(unsigned char *buf, size_t buflen, ...) {
	va_list args;
	int retval;

	va_start(args, buflen);

	retval = _asn1_x509_read_asn1_object(buf, buflen, &args);

	va_end(args);

	return(retval);
}

static int asn1_x509_read_object(unsigned char *buf, size_t buflen, struct x509_object *outbuf) {
	int read_ret;

	read_ret = asn1_x509_read_asn1_object(buf, buflen, &outbuf->wholething, NULL);
	if (read_ret != 0) {
//		CACKEY_DEBUG_PRINTF("Failed at reading the contents from the wrapper");

		return(-1);
	}

	read_ret = asn1_x509_read_asn1_object(outbuf->wholething.contents, outbuf->wholething.size, &outbuf->certificate, NULL);
	if (read_ret != 0) {
//		CACKEY_DEBUG_PRINTF("Failed at reading the certificate from the contents");

		return(-1);
	}

	read_ret = asn1_x509_read_asn1_object(outbuf->certificate.contents, outbuf->certificate.size, &outbuf->version, &outbuf->serial_number, &outbuf->signature_algo, &outbuf->issuer, &outbuf->validity, &outbuf->subject, &outbuf->pubkeyinfo, NULL);
	if (read_ret != 0) {
		/* Try again without a version tag (X.509v1) */
		outbuf->version.tag = 0;
		outbuf->version.size = 0;
		outbuf->version.contents = NULL;
		outbuf->version.asn1rep_len = 0;
		outbuf->version.asn1rep = NULL;
		read_ret = asn1_x509_read_asn1_object(outbuf->certificate.contents, outbuf->certificate.size, &outbuf->serial_number, &outbuf->signature_algo, &outbuf->issuer, &outbuf->validity, &outbuf->subject, &outbuf->pubkeyinfo, NULL);
		if (read_ret != 0) {
//			CACKEY_DEBUG_PRINTF("Failed at reading the certificate components from the certificate");

			return(-1);
		}
	}

	read_ret = asn1_x509_read_asn1_object(outbuf->pubkeyinfo.contents, outbuf->pubkeyinfo.size, &outbuf->pubkey_algoid, &outbuf->pubkey, NULL);
	if (read_ret != 0) {
//		CACKEY_DEBUG_PRINTF("Failed at reading the public key from the certificate components");

		return(-1);
	}

	return(0);
}

/////////////End Parse Certificate///////////////////////////////////


struct tclpkcs11_interpdata {
	/* Handle Hash Table */
	Tcl_HashTable handles;
	unsigned long handles_idx;
};

struct tclpkcs11_handle {
	/* PKCS11 Module Pointers */
	void *base;
	CK_FUNCTION_LIST_PTR pkcs11;

	/* Session Management */
	int session_active;
	CK_SLOT_ID session_slot;
	CK_SESSION_HANDLE session;
};

/*
 * Tcl <--> PKCS11 Bridge Functions
 */ 
MODULE_SCOPE Tcl_Obj *tclpkcs11_pkcs11_error(CK_RV errorCode) {
	switch (errorCode) {
		case CKR_OK:
			return(Tcl_NewStringObj("PKCS11_OK OK", -1));
		case CKR_CANCEL:
			return(Tcl_NewStringObj("PKCS11_ERROR CANCEL", -1));
		case CKR_HOST_MEMORY:
			return(Tcl_NewStringObj("PKCS11_ERROR HOST_MEMORY", -1));
		case CKR_SLOT_ID_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SLOT_ID_INVALID", -1));
		case CKR_GENERAL_ERROR:
			return(Tcl_NewStringObj("PKCS11_ERROR GENERAL_ERROR", -1));
		case CKR_FUNCTION_FAILED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_FAILED", -1));
		case CKR_ARGUMENTS_BAD:
			return(Tcl_NewStringObj("PKCS11_ERROR ARGUMENTS_BAD", -1));
		case CKR_NO_EVENT:
			return(Tcl_NewStringObj("PKCS11_ERROR NO_EVENT", -1));
		case CKR_NEED_TO_CREATE_THREADS:
			return(Tcl_NewStringObj("PKCS11_ERROR NEED_TO_CREATE_THREADS", -1));
		case CKR_CANT_LOCK:
			return(Tcl_NewStringObj("PKCS11_ERROR CANT_LOCK", -1));
		case CKR_ATTRIBUTE_READ_ONLY:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_READ_ONLY", -1));
		case CKR_ATTRIBUTE_SENSITIVE:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_SENSITIVE", -1));
		case CKR_ATTRIBUTE_TYPE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_TYPE_INVALID", -1));
		case CKR_ATTRIBUTE_VALUE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_VALUE_INVALID", -1));
		case CKR_DATA_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR DATA_INVALID", -1));
		case CKR_DATA_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR DATA_LEN_RANGE", -1));
		case CKR_DEVICE_ERROR:
			return(Tcl_NewStringObj("PKCS11_ERROR DEVICE_ERROR", -1));
		case CKR_DEVICE_MEMORY:
			return(Tcl_NewStringObj("PKCS11_ERROR DEVICE_MEMORY", -1));
		case CKR_DEVICE_REMOVED:
			return(Tcl_NewStringObj("PKCS11_ERROR DEVICE_REMOVED", -1));
		case CKR_ENCRYPTED_DATA_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR ENCRYPTED_DATA_INVALID", -1));
		case CKR_ENCRYPTED_DATA_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR ENCRYPTED_DATA_LEN_RANGE", -1));
		case CKR_FUNCTION_CANCELED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_CANCELED", -1));
		case CKR_FUNCTION_NOT_PARALLEL:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_NOT_PARALLEL", -1));
		case CKR_FUNCTION_NOT_SUPPORTED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_NOT_SUPPORTED", -1));
		case CKR_KEY_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_HANDLE_INVALID", -1));
		case CKR_KEY_SIZE_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_SIZE_RANGE", -1));
		case CKR_KEY_TYPE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_TYPE_INCONSISTENT", -1));
		case CKR_KEY_NOT_NEEDED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_NOT_NEEDED", -1));
		case CKR_KEY_CHANGED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_CHANGED", -1));
		case CKR_KEY_NEEDED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_NEEDED", -1));
		case CKR_KEY_INDIGESTIBLE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_INDIGESTIBLE", -1));
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_FUNCTION_NOT_PERMITTED", -1));
		case CKR_KEY_NOT_WRAPPABLE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_NOT_WRAPPABLE", -1));
		case CKR_KEY_UNEXTRACTABLE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_UNEXTRACTABLE", -1));
		case CKR_MECHANISM_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR MECHANISM_INVALID", -1));
		case CKR_MECHANISM_PARAM_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR MECHANISM_PARAM_INVALID", -1));
		case CKR_OBJECT_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR OBJECT_HANDLE_INVALID", -1));
		case CKR_OPERATION_ACTIVE:
			return(Tcl_NewStringObj("PKCS11_ERROR OPERATION_ACTIVE", -1));
		case CKR_OPERATION_NOT_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR OPERATION_NOT_INITIALIZED", -1));
		case CKR_PIN_INCORRECT:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_INCORRECT", -1));
		case CKR_PIN_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_INVALID", -1));
		case CKR_PIN_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_LEN_RANGE", -1));
		case CKR_PIN_EXPIRED:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_EXPIRED", -1));
		case CKR_PIN_LOCKED:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_LOCKED", -1));
		case CKR_SESSION_CLOSED:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_CLOSED", -1));
		case CKR_SESSION_COUNT:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_COUNT", -1));
		case CKR_SESSION_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_HANDLE_INVALID", -1));
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_PARALLEL_NOT_SUPPORTED", -1));
		case CKR_SESSION_READ_ONLY:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_READ_ONLY", -1));
		case CKR_SESSION_EXISTS:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_EXISTS", -1));
		case CKR_SESSION_READ_ONLY_EXISTS:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_READ_ONLY_EXISTS", -1));
		case CKR_SESSION_READ_WRITE_SO_EXISTS:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_READ_WRITE_SO_EXISTS", -1));
		case CKR_SIGNATURE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SIGNATURE_INVALID", -1));
		case CKR_SIGNATURE_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR SIGNATURE_LEN_RANGE", -1));
		case CKR_TEMPLATE_INCOMPLETE:
			return(Tcl_NewStringObj("PKCS11_ERROR TEMPLATE_INCOMPLETE", -1));
		case CKR_TEMPLATE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR TEMPLATE_INCONSISTENT", -1));
		case CKR_TOKEN_NOT_PRESENT:
			return(Tcl_NewStringObj("PKCS11_ERROR TOKEN_NOT_PRESENT", -1));
		case CKR_TOKEN_NOT_RECOGNIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR TOKEN_NOT_RECOGNIZED", -1));
		case CKR_TOKEN_WRITE_PROTECTED:
			return(Tcl_NewStringObj("PKCS11_ERROR TOKEN_WRITE_PROTECTED", -1));
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR UNWRAPPING_KEY_HANDLE_INVALID", -1));
		case CKR_UNWRAPPING_KEY_SIZE_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR UNWRAPPING_KEY_SIZE_RANGE", -1));
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR UNWRAPPING_KEY_TYPE_INCONSISTENT", -1));
		case CKR_USER_ALREADY_LOGGED_IN:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_ALREADY_LOGGED_IN", -1));
		case CKR_USER_NOT_LOGGED_IN:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_NOT_LOGGED_IN", -1));
		case CKR_USER_PIN_NOT_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_PIN_NOT_INITIALIZED", -1));
		case CKR_USER_TYPE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_TYPE_INVALID", -1));
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_ANOTHER_ALREADY_LOGGED_IN", -1));
		case CKR_USER_TOO_MANY_TYPES:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_TOO_MANY_TYPES", -1));
		case CKR_WRAPPED_KEY_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPED_KEY_INVALID", -1));
		case CKR_WRAPPED_KEY_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPED_KEY_LEN_RANGE", -1));
		case CKR_WRAPPING_KEY_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPING_KEY_HANDLE_INVALID", -1));
		case CKR_WRAPPING_KEY_SIZE_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPING_KEY_SIZE_RANGE", -1));
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPING_KEY_TYPE_INCONSISTENT", -1));
		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			return(Tcl_NewStringObj("PKCS11_ERROR RANDOM_SEED_NOT_SUPPORTED", -1));
		case CKR_RANDOM_NO_RNG:
			return(Tcl_NewStringObj("PKCS11_ERROR RANDOM_NO_RNG", -1));
		case CKR_DOMAIN_PARAMS_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR DOMAIN_PARAMS_INVALID", -1));
		case CKR_BUFFER_TOO_SMALL:
			return(Tcl_NewStringObj("PKCS11_ERROR BUFFER_TOO_SMALL", -1));
		case CKR_SAVED_STATE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SAVED_STATE_INVALID", -1));
		case CKR_INFORMATION_SENSITIVE:
			return(Tcl_NewStringObj("PKCS11_ERROR INFORMATION_SENSITIVE", -1));
		case CKR_STATE_UNSAVEABLE:
			return(Tcl_NewStringObj("PKCS11_ERROR STATE_UNSAVEABLE", -1));
		case CKR_CRYPTOKI_NOT_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR CRYPTOKI_NOT_INITIALIZED", -1));
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR CRYPTOKI_ALREADY_INITIALIZED", -1));
		case CKR_MUTEX_BAD:
			return(Tcl_NewStringObj("PKCS11_ERROR MUTEX_BAD", -1));
		case CKR_MUTEX_NOT_LOCKED:
			return(Tcl_NewStringObj("PKCS11_ERROR MUTEX_NOT_LOCKED", -1));
		case CKR_NEW_PIN_MODE:
			return(Tcl_NewStringObj("PKCS11_ERROR NEW_PIN_MODE", -1));
		case CKR_NEXT_OTP:
			return(Tcl_NewStringObj("PKCS11_ERROR NEXT_OTP", -1));
		case CKR_FUNCTION_REJECTED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_REJECTED", -1));
		case CKR_VENDOR_DEFINED:
			return(Tcl_NewStringObj("PKCS11_ERROR VENDOR_DEFINED", -1));
	}

	return(Tcl_NewStringObj("PKCS11_ERROR UNKNOWN", -1));
}
/*LISSI*/
char *get_mechanism_name(CK_ULONG mech)
{
	switch (mech) {
    case CKM_GOSTR3410_KEY_PAIR_GEN:
      return "CKM_GOSTR3410_KEY_PAIR_GEN";
    case CKM_GOSTR3410_512_KEY_PAIR_GEN:
      return "CKM_GOSTR3410_512_KEY_PAIR_GEN";
    case CKM_GOSTR3410:
      return "CKM_GOSTR3410";
    case CKM_GOSTR3410_512:
      return "CKM_GOSTR3410_512";
    case CKM_GOSTR3410_WITH_GOSTR3411:
      return "CKM_GOSTR3410_WITH_GOSTR3411";
    case CKM_GOSTR3410_WITH_GOSTR3411_12_256:
      return "CKM_GOSTR3410_WITH_GOSTR3411_12_256";
    case CKM_GOSTR3410_WITH_GOSTR3411_12_512:
      return "CKM_GOSTR3410_WITH_GOSTR3411_12_512";
    case CKM_GOSTR3410_KEY_WRAP:
      return "CKM_GOSTR3410_KEY_WRAP";
    case CKM_GOSTR3410_DERIVE:
      return "CKM_GOSTR3410_DERIVE";
    case CKM_GOSTR3410_12_DERIVE:
      return "CKM_GOSTR3410_12_DERIVE";
    case CKM_GOSTR3410_2012_VKO_256:
      return "CKM_GOSR3410_2012_VKO_256";
    case CKM_GOSTR3410_2012_VKO_512:
      return "CKM_GOSR3410_2012_VKO_512";
    case CKM_KDF_4357:
      return "CKM_KDF_4357";
    case CKM_KDF_GOSTR3411_2012_256:
      return "CKM_KDF_GOSTR3411_2012_256";
    case CKM_KDF_TREE_GOSTR3411_2012_256:
      return "CKM_KDF_TREE_GOSTR3411_2012_256";
    case CKM_GOSTR3411:
      return "CKM_GOSTR3411";
    case CKM_GOSTR3411_12_256:
      return "CKM_GOSTR3411_12_256";
    case CKM_GOSTR3411_12_512:
      return "CKM_GOSTR3411_12_512";
    case CKM_GOSTR3411_HMAC:
      return "CKM_GOSTR3411_HMAC";
    case CKM_GOSTR3411_12_256_HMAC:
      return "CKM_GOSTR3411_12_256_HMAC";
    case CKM_GOSTR3411_12_512_HMAC:
      return "CKM_GOSTR3411_12_512_HMAC";
    case CKM_GOST_GENERIC_SECRET_KEY_GEN:
      return "CKM_GOST_GENERIC_SECRET_KEY_GEN";
    case CKM_GOST_CIPHER_KEY_GEN:
      return "CKM_GOST_CIPHER_KEY_GEN";
    case CKM_GOST_CIPHER_ECB:
      return "CKM_GOST_CIPHER_ECB";
    case CKM_GOST_CIPHER_CBC:
      return "CKM_GOST_CIPHER_CBC";
    case CKM_GOST_CIPHER_CTR:
      return "CKM_GOST_CIPHER_CTR";
    case CKM_GOST_CIPHER_OFB:
      return "CKM_GOST_CIPHER_OFB";
    case CKM_GOST_CIPHER_CFB:
      return "CKM_GOST_CIPHER_CFB";
    case CKM_GOST_CIPHER_OMAC:
      return "CKM_GOST_CIPHER_OMAC";
    case CKM_GOST_CIPHER_ACPKM_CTR:
      return "CKM_GOST_CIPHER_ACPKM_CTR";
    case CKM_GOST_CIPHER_ACPKM_OMAC:
      return "CKM_GOST_CIPHER_ACPKM_OMAC";
    case CKM_GOST_CIPHER_KEY_WRAP:
      return "CKM_GOST_CIPHER_KEY_WRAP";
    case CKM_GOST_CIPHER_PKCS8_KEY_WRAP:
      return "CKM_GOST_CIPHER_PKCS8_KEY_WRAP";
    case CKM_GOST28147_KEY_GEN:
      return "CKM_GOST28147_KEY_GEN";
    case CKM_GOST28147_ECB:
      return "CKM_GOST28147_ECB";
    case CKM_GOST28147:
      return "CKM_GOST28147";
    case CKM_GOST28147_MAC:
      return "CKM_GOST28147_MAC";
    case CKM_GOST28147_KEY_WRAP:
      return "CKM_GOST28147_KEY_WRAP";
    case CKM_GOST28147_CNT:
      return "CKM_GOST28147_CNT";
    case CKM_KUZNYECHIK_KEY_GEN:
      return "CKM_KUZNYECHIK_KEY_GEN";
    case CKM_KUZNYECHIK_ECB:
      return "CKM_KUZNYECHIK_ECB";
    case CKM_KUZNYECHIK_CBC:
      return "CKM_KUZNYECHIK_CBC";
    case CKM_KUZNYECHIK_CTR:
      return "CKM_KUZNYECHIK_CTR";
    case CKM_KUZNYECHIK_OFB:
      return "CKM_KUZNYECHIK_OFB";
    case CKM_KUZNYECHIK_CFB:
      return "CKM_KUZNYECHIK_CFB";
    case CKM_KUZNYECHIK_OMAC:
      return "CKM_KUZNYECHIK_OMAC";
    case CKM_KUZNYECHIK_ACPKM_CTR:
      return "CKM_KUZNYECHIK_ACPKM_CTR";
    case CKM_KUZNYECHIK_ACPKM_OMAC:
      return "CKM_KUZNYECHIK_ACPKM_OMAC";
    case CKM_KUZNYECHIK_KEY_WRAP:
      return "CKM_KUZNYECHIK_KEY_WRAP";
    case CKM_MAGMA_KEY_GEN:
      return "CKM_MAGMA_KEY_GEN";
    case CKM_MAGMA_ECB:
      return "CKM_MAGMA_ECB";
    case CKM_MAGMA_CBC:
      return "CKM_MAGMA_CBC";
    case CKM_MAGMA_CTR:
      return "CKM_MAGMA_CTR";
    case CKM_MAGMA_OFB:
      return "CKM_MAGMA_OFB";
    case CKM_MAGMA_CFB:
      return "CKM_MAGMA_CFB";
    case CKM_MAGMA_OMAC:
      return "CKM_MAGMA_OMAC";
    case CKM_MAGMA_ACPKM_CTR:
      return "CKM_MAGMA_ACPKM_CTR";
    case CKM_MAGMA_ACPKM_OMAC:
      return "CKM_MAGMA_ACPKM_OMAC";
    case CKM_MAGMA_KEY_WRAP:
      return "CKM_MAGMA_KEY_WRAP";
    case CKM_TLS_GOST_PRF:
      return "CKM_TLS_GOST_PRF";
    case CKM_TLS_GOST_PRE_MASTER_KEY_GEN:
      return "CKM_TLS_GOST_PRE_MASTER_KEY_GEN";
    case CKM_TLS_GOST_MASTER_KEY_DERIVE:
      return "CKM_TLS_GOST_MASTER_KEY_DERIVE";
    case CKM_TLS_GOST_KEY_AND_MAC_DERIVE:
      return "CKM_TLS_GOST_KEY_AND_MAC_DERIVE";
    case CKM_TLS_GOST_PRF_2012_256:
      return "CKM_TLS_GOST_PRF_2012_256";
    case CKM_TLS_GOST_PRF_2012_512:
      return "CKM_TLS_GOST_PRF_2012_512";
    case CKM_TLS12_MASTER_KEY_DERIVE:
      return "CKM_TLS12_MASTER_KEY_DERIVE";
    case CKM_TLS12_KEY_AND_MAC_DERIVE:
      return "CKM_TLS12_KEY_AND_MAC_DERIVE";
    case CKM_TLS_MAC:
      return "CKM_TLS_MAC";
    case CKM_TLS_KDF:
      return "CKM_TLS_KDF";
    case CKM_TLS_TREE_GOSTR3411_2012_256:
      return "CKM_TLS_TREE_GOSTR3411_2012_256";
    case CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC:
      return "CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC";
    case CKM_GOST28147_PKCS8_KEY_WRAP:
      return "CKM_GOST28147_PKCS8_KEY_WRAP";
    case CKM_GOSTR3410_PUBLIC_KEY_DERIVE:
      return "CKM_GOSTR3410_PUBLIC_KEY_DERIVE";
    case CKM_LISSI_GOSTR3410_PUBLIC_KEY_DERIVE:
      return "CKM_LISSI_GOSTR3410_PUBLIC_KEY_DERIVE";
	  case CKM_EXTRACT_KEY_FROM_KEY:
		  return "CKM_EXTRACT_KEY_FROM_KEY";
    case CKM_PKCS5_PBKD2:
      return "CKM_PKCS5_PBKD2";
    case CKM_SHA_1:
      return "CKM_SHA_1";
    case CKM_MD5:
      return "CKM_MD5";
    case CKM_VENDOR_DEFINED: 
		  return "CKM_VENDOR_DEFINED";
	  default: 
      return (char *)NULL;
	}
}


MODULE_SCOPE Tcl_Obj *tclpkcs11_bytearray_to_string(const unsigned char *data, unsigned long datalen) {
	static char alphabet[] = "0123456789abcdef";
	unsigned long idx, bufidx;
	Tcl_Obj *retval;
/*LISSI*/
//	char buf[1024];
	unsigned char *buf;
//fprintf (stderr, "tclpkcs11_bytearray_to_string: LEN1=%lu\n", datalen);
	buf = (unsigned char *) malloc(datalen*2 + 1);

	if (data == NULL) {
		return(Tcl_NewObj());
	}

/*LISSI*/
//	for (bufidx = idx = 0; (idx < datalen) && (bufidx < sizeof(buf)); idx++) {
	for (bufidx = idx = 0; (idx < datalen) && (bufidx < (datalen*2 + 1)); idx++) {

		buf[bufidx++] = alphabet[(data[idx] >> 4) & 0xf];
		buf[bufidx++] = alphabet[data[idx] & 0xf];
	}

	retval = Tcl_NewByteArrayObj((unsigned char *) buf, bufidx);
	free(buf);
	return(retval);
}

MODULE_SCOPE unsigned long tclpkcs11_string_to_bytearray(Tcl_Obj *data, unsigned char *outbuf, unsigned long outbuflen) {
	unsigned long outbufidx = 0;
	char tmpbuf[5];
	char *str;
	int tmpint;
	int tcl_rv;

	if (outbuf == NULL) {
		return(0);
	}

	str = Tcl_GetString(data);
	if (!str) {
		return(0);
	}

	tmpbuf[0] = '0';
	tmpbuf[1] = 'x';
	tmpbuf[4] = '\0';

	for (str = Tcl_GetString(data); *str; str++) {
		tmpbuf[2] = *str;

		str++;
		if (!*str) {
			break;
		}

		tmpbuf[3] = *str;

		tcl_rv = Tcl_GetInt(NULL, tmpbuf, &tmpint);
		if (tcl_rv != TCL_OK) {
			return(0);
		}

		outbuf[outbufidx] = tmpint;
		outbufidx++;

		if (outbufidx >= outbuflen) {
			break;
		}
	}

	return(outbufidx);
}

/* PKCS#11 Mutex functions implementation that use Tcl Mutexes */
MODULE_SCOPE CK_RV tclpkcs11_create_mutex(void **mutex) {
	Tcl_Mutex *retval;

	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	retval = (Tcl_Mutex *) ckalloc(sizeof(*retval));
	memset(retval, 0, sizeof(*retval));

	*mutex = retval;

	return(CKR_OK);
}

MODULE_SCOPE CK_RV tclpkcs11_lock_mutex(void *mutex) {
	Tcl_Mutex *tcl_mutex;

	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	tcl_mutex = mutex;

	Tcl_MutexLock(tcl_mutex);

	return(CKR_OK);
}

MODULE_SCOPE CK_RV tclpkcs11_unlock_mutex(void *mutex) {
	Tcl_Mutex *tcl_mutex;

	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	tcl_mutex = mutex;

	Tcl_MutexUnlock(tcl_mutex);

	return(CKR_OK);
}

MODULE_SCOPE CK_RV tclpkcs11_destroy_mutex(void *mutex) {
	Tcl_Mutex *tcl_mutex;

	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	tcl_mutex = mutex;

	Tcl_MutexFinalize(tcl_mutex);
	ckfree(mutex);

	return(CKR_OK);
}

/* Convience function to start a session if one is not already active */
MODULE_SCOPE int tclpkcs11_start_session(struct tclpkcs11_handle *handle, CK_SLOT_ID slot) {
	CK_SESSION_HANDLE tmp_session;
	CK_RV chk_rv;

	if (handle->session_active) {
		if (handle->session_slot == slot) {
			return(CKR_OK);
		}

		/* Close the existing session and create a new one */
		handle->session_active = 0;
		chk_rv = handle->pkcs11->C_CloseSession(handle->session);
		if (chk_rv != CKR_OK) {
			return(chk_rv);
		}
	}

/*LISSI*/
/*	chk_rv = handle->pkcs11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &tmp_session);*/
	chk_rv = handle->pkcs11->C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &tmp_session);

	if (chk_rv != CKR_OK) {
		handle->pkcs11->C_CloseSession(handle->session);

		return(chk_rv);
	}

	handle->session = tmp_session;
	handle->session_slot = slot;
	handle->session_active = 1;

	return(CKR_OK);
}

MODULE_SCOPE int tclpkcs11_close_session(struct tclpkcs11_handle *handle) {
	CK_RV chk_rv;

	if (handle->session_active) {
		handle->session_active = 0;
		chk_rv = handle->pkcs11->C_CloseSession(handle->session);

		if (chk_rv != CKR_OK) {
			return(chk_rv);
		}
	}

	return(CKR_OK);
}

/*
 * Platform Specific Functions 
 */
MODULE_SCOPE void *tclpkcs11_int_load_module(const char *pathname) {
#if defined(TCL_INCLUDES_LOADFILE)
	int tcl_rv;
	Tcl_LoadHandle *new_handle;

	new_handle = (Tcl_LoadHandle *) ckalloc(sizeof(*new_handle));

	tcl_rv = Tcl_LoadFile(NULL, Tcl_NewStringObj(pathname, -1), NULL, 0, NULL, new_handle);
	if (tcl_rv != TCL_OK) {
		return(NULL);
	}

	return(new_handle);
#elif defined(HAVE_DLOPEN)
/*LISSI*/
//fprintf (stderr, "tclpkcs11_int_load_module=%s\n", pathname);
	return(dlopen(pathname, RTLD_NOW /*| RTLD_GLOBAL*/));
/*	return(dlopen(pathname, RTLD_NOW | RTLD_GLOBAL));*/
	
#elif defined(HAVE_SHL_LOAD)
	return(shl_load(pathname, BIND_DEFERRED, 0L));
#elif defined(_WIN32)
/*LISSI*/
	char cp1251[2048];
	memset(cp1251, '\0', 2048);
	utf8_to_win1251((const char*) pathname, cp1251);

	return(LoadLibraryA(cp1251));
//	return(LoadLibrary(pathname));
#endif
	return(NULL);
}
MODULE_SCOPE void tclpkcs11_int_unload_module(void *handle) {
#if defined(TCL_INCLUDES_LOADFILE)
	Tcl_LoadHandle *tcl_handle;

	tcl_handle = handle;

	Tcl_FSUnloadFile(NULL, *tcl_handle);

	ckfree(handle);
#elif defined(HAVE_DLOPEN)
	dlclose(handle);
#elif defined(HAVE_SHL_LOAD)
	shl_unload(handle);
#elif defined(_WIN32)
	FreeLibrary(handle);
#endif
	return;
}
MODULE_SCOPE void *tclpkcs11_int_lookup_sym(void *handle, const char *sym) {
#if defined(TCL_INCLUDES_LOADFILE)
	Tcl_LoadHandle *tcl_handle;
	void *retval;

	tcl_handle = handle;

	retval = Tcl_FindSymbol(NULL, *tcl_handle, sym);

	return(retval);
#elif defined(HAVE_DLOPEN)
	return(dlsym(handle, sym));
#elif defined(HAVE_SHL_LOAD)
	void *retval;
	int shl_findsym_ret;

	shl_findsym_ret = shl_findsym(handle, sym, TYPE_PROCEDURE, &retval);
	if (shl_findsym_ret != 0) {
		return(NULL);
	}

	return(retval);
#elif defined(_WIN32)
	return(GetProcAddress(handle, sym));
#endif
	return(NULL);
}

/*
 * Tcl Commands
 */
MODULE_SCOPE int tclpkcs11_load_module(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *new_handle;
	const char *pathname;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle;
	void *handle;
	int is_new_entry;
/*LISSI*/
//fprintf (stderr, "tclpkcs11_load_module: START\n");

	CK_C_INITIALIZE_ARGS initargs;
	CK_C_GetFunctionList getFuncList;
	CK_FUNCTION_LIST_PTR pkcs11_function_list = NULL;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata\n", -1));

		return(TCL_ERROR);
	}

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::loadmodule filename\"", -1));

		return(TCL_ERROR);
	}

	pathname = Tcl_GetString(objv[1]);
	if (!pathname) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid pathname", -1));

		return(TCL_ERROR);
	}

	handle = tclpkcs11_int_load_module(pathname);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to load", -1));

		return(TCL_ERROR);
	}

	getFuncList = tclpkcs11_int_lookup_sym(handle, "C_GetFunctionList");
	if (!getFuncList) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to locate C_GetFunctionList symbol in PKCS#11 module", -1));

		return(TCL_ERROR);
	}

	chk_rv = getFuncList(&pkcs11_function_list);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	if (!pkcs11_function_list) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetFunctionList returned invalid data", -1));

		return(TCL_ERROR);
	}

	if (!pkcs11_function_list->C_Initialize) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetFunctionList returned incomplete data", -1));

		return(TCL_ERROR);
	}
/*LISSI*/
//fprintf (stderr, "tclpkcs11_load_module: 10\n");

	initargs.CreateMutex = tclpkcs11_create_mutex;
	initargs.DestroyMutex = tclpkcs11_destroy_mutex;
	initargs.LockMutex = tclpkcs11_lock_mutex;
	initargs.UnlockMutex = tclpkcs11_unlock_mutex;
	initargs.flags = 0;
/*LISSI*/
	initargs.LibraryParameters = NULL;
/*	initargs.LibraryFlags = NULL;*/

	initargs.pReserved = NULL;

	chk_rv = pkcs11_function_list->C_Initialize(&initargs);
	if (chk_rv != CKR_OK) {
/*LISSI*/
//fprintf (stderr, "tclpkcs11_load_module: 11 pathname=%s\n", pathname);
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle = Tcl_NewStringObj("pkcsmod", -1);
	Tcl_AppendObjToObj(tcl_handle, Tcl_NewLongObj(interpdata->handles_idx));
	(interpdata->handles_idx)++;

	tcl_handle_entry = Tcl_CreateHashEntry(&interpdata->handles, (const char *) tcl_handle, &is_new_entry);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create new hash entry", -1));

		return(TCL_ERROR);
	}

	/* Allocate the per-handle structure */
	new_handle = (struct tclpkcs11_handle *) ckalloc(sizeof(*new_handle));

	/* Initialize the per-handle structure */
	new_handle->base = handle;
	new_handle->pkcs11 = pkcs11_function_list;
	new_handle->session_active = 0;

	Tcl_SetHashValue(tcl_handle_entry, (ClientData) new_handle);

	Tcl_SetObjResult(interp, tcl_handle);
/*LISSI*/
//fprintf (stderr, "tclpkcs11_load_module: END\n");

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_unload_module(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle;

	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::unloadmodule handle\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	/* Log out of the PKCS11 module */
	handle->pkcs11->C_Logout(handle->session);

	/* Close the session, cleaning up all the session objects */
	tclpkcs11_close_session(handle);

	/* Ask the PKCS#11 Provider to terminate */
	chk_rv = handle->pkcs11->C_Finalize(NULL);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* Delete our hash entry */
	Tcl_DeleteHashEntry(tcl_handle_entry);

	/* Attempt to unload the module */
	tclpkcs11_int_unload_module(handle->base);

	/* Free our allocated handle */
	ckfree((char *) handle);

	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_list_slots(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle;
	Tcl_Obj *ret_list, *curr_item_list, *flags_list, *slot_desc, *token_desc;

	CK_SLOT_ID_PTR slots;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_ULONG numSlots, currSlot;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::listslots handle\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_GetSlotList(FALSE, NULL, &numSlots);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	slots = (CK_SLOT_ID_PTR) ckalloc(sizeof(*slots) * numSlots);

	chk_rv = handle->pkcs11->C_GetSlotList(FALSE, slots, &numSlots);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	ret_list = Tcl_NewObj();

	for (currSlot = 0; currSlot < numSlots; currSlot++) {
		chk_rv = handle->pkcs11->C_GetSlotInfo(slots[currSlot], &slotInfo);

		curr_item_list = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewLongObj(slots[currSlot]));

		flags_list = Tcl_NewObj();

		if (chk_rv != CKR_OK) {
			/* Add an empty string as the token label */
			Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("", 0));

			/* Add the list of existing flags (none) */
			Tcl_ListObjAppendElement(interp, curr_item_list, flags_list);

			/* Add this item to the list */
			Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);

			continue;
		}

		slot_desc = NULL;
		token_desc = Tcl_NewObj();

		if ((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT) {
			Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("TOKEN_PRESENT", -1));

			chk_rv = handle->pkcs11->C_GetTokenInfo(slots[currSlot], &tokenInfo);

			if (chk_rv == CKR_OK) {
				/* Add the token label as the slot label */
				if (!slot_desc) {
					slot_desc = Tcl_NewStringObj((const char *) tokenInfo.label, 32);
					Tcl_ListObjAppendElement(interp, token_desc, Tcl_NewStringObj((const char *) tokenInfo.label, 32));
					Tcl_ListObjAppendElement(interp, token_desc, Tcl_NewStringObj((const char *) tokenInfo.manufacturerID, 32));
					Tcl_ListObjAppendElement(interp, token_desc, Tcl_NewStringObj((const char *) tokenInfo.model, 16));
					Tcl_ListObjAppendElement(interp, token_desc, Tcl_NewStringObj((const char *) tokenInfo.serialNumber, 16));
				}

				if ((tokenInfo.flags & CKF_RNG) == CKF_RNG) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("RNG", -1));
				}
				if ((tokenInfo.flags & CKF_WRITE_PROTECTED) == CKF_WRITE_PROTECTED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("WRITE_PROTECTED", -1));
				}
				if ((tokenInfo.flags & CKF_LOGIN_REQUIRED) == CKF_LOGIN_REQUIRED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("LOGIN_REQUIRED", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == CKF_USER_PIN_INITIALIZED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_INITIALIZED", -1));
				}
				if ((tokenInfo.flags & CKF_RESTORE_KEY_NOT_NEEDED) == CKF_RESTORE_KEY_NOT_NEEDED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("RESTORE_KEY_NOT_NEEDED", -1));
				}
				if ((tokenInfo.flags & CKF_CLOCK_ON_TOKEN) == CKF_CLOCK_ON_TOKEN) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("CLOCK_ON_TOKEN", -1));
				}
				if ((tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("PROTECTED_AUTHENTICATION_PATH", -1));
				}
				if ((tokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS) == CKF_DUAL_CRYPTO_OPERATIONS) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("DUAL_CRYPTO_OPERATIONS", -1));
				}
				if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("TOKEN_INITIALIZED", -1));
				}
				if ((tokenInfo.flags & CKF_SECONDARY_AUTHENTICATION) == CKF_SECONDARY_AUTHENTICATION) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SECONDARY_AUTHENTICATION", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_COUNT_LOW) == CKF_USER_PIN_COUNT_LOW) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_COUNT_LOW", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_FINAL_TRY) == CKF_USER_PIN_FINAL_TRY) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_FINAL_TRY", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_LOCKED) == CKF_USER_PIN_LOCKED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_LOCKED", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_TO_BE_CHANGED) == CKF_USER_PIN_TO_BE_CHANGED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_TO_BE_CHANGED", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_COUNT_LOW) == CKF_SO_PIN_COUNT_LOW) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_COUNT_LOW", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_FINAL_TRY) == CKF_SO_PIN_FINAL_TRY) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_FINAL_TRY", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_LOCKED) == CKF_SO_PIN_LOCKED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_LOCKED", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_TO_BE_CHANGED) == CKF_SO_PIN_TO_BE_CHANGED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_TO_BE_CHANGED", -1));
				}
			}
		}

		/* Add additional slot flags */
		if ((slotInfo.flags & CKF_REMOVABLE_DEVICE) == CKF_REMOVABLE_DEVICE) {
			Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("REMOVABLE_DEVICE", -1));
		}
		if ((slotInfo.flags & CKF_HW_SLOT) == CKF_HW_SLOT) {
			Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("HW_SLOT", -1));
		}

		if (slot_desc) {
			/* If we found a more descriptive slot description, use it */
			Tcl_ListObjAppendElement(interp, curr_item_list, slot_desc);
		} else {
			/* Add the slot description as the label for tokens with nothing in them */
			Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj((const char *) slotInfo.slotDescription, 32));
		}
		
		Tcl_ListObjAppendElement(interp, curr_item_list, flags_list);

/*Descryption token*/
		Tcl_ListObjAppendElement(interp, curr_item_list, token_desc);

		Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);
	}

	Tcl_SetObjResult(interp, ret_list);

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_list_certs(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid;
	long slotid_long;
	Tcl_Obj *obj_label, *obj_cert, *obj_id;
	Tcl_Obj *ret_list, *curr_item_list;
	Tcl_Obj *parse_cert_cmd;
	int tcl_rv;
/*LISSI*/
	int type_cert;

	CK_SLOT_ID slotid;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG ulObjectCount;
	CK_ATTRIBUTE template[] = {
	                           {CKA_CLASS, NULL, 0},
	                           {CKA_LABEL, NULL, 0},
	                           {CKA_ID, NULL, 0},
	                           {CKA_VALUE, NULL, 0}
	}, *curr_attr;
	CK_ULONG curr_attr_idx;
	CK_OBJECT_CLASS *objectclass;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::listcerts handle slot\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, NULL, 0);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	ret_list = Tcl_NewObj();
	while (1) {
/*LISSI*/
		type_cert = 0;	

		chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &ulObjectCount);
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		if (ulObjectCount == 0) {
			break;
		}

		if (ulObjectCount != 1) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("FindObjects() returned a weird number of objects.", -1));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];
			if (curr_attr->pValue) {
				ckfree(curr_attr->pValue);
			}

			curr_attr->pValue = NULL;
			curr_attr->ulValueLen = 0;
		}

		/* Determine size of values to allocate */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
		if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
			chk_rv = CKR_OK;
		}

		if (chk_rv != CKR_OK) {
			/* Skip this object if we are not able to process it */
			continue;
		}

		/* Allocate values */
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];

			if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
				curr_attr->pValue = (void *) ckalloc(curr_attr->ulValueLen);
			}
		}

		/* Populate template values */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
		if (chk_rv != CKR_OK && chk_rv != CKR_ATTRIBUTE_SENSITIVE && chk_rv != CKR_ATTRIBUTE_TYPE_INVALID && chk_rv != CKR_BUFFER_TOO_SMALL) {
			/* Return an error if we are unable to process this entry due to unexpected errors */
			for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
				curr_attr = &template[curr_attr_idx];
				if (curr_attr->pValue) {
					ckfree(curr_attr->pValue);
				}
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		/* Extract certificate data */
		obj_label = NULL;
		obj_id = NULL;
		obj_cert = NULL;
		objectclass = NULL;
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];

			if (!curr_attr->pValue) {
				continue;
			}

			switch (curr_attr->type) {
				case CKA_CLASS:
					objectclass = (CK_OBJECT_CLASS *) curr_attr->pValue;

					if (*objectclass != CKO_CERTIFICATE) {
						continue;
					}
/*LISSI*/
					type_cert = 1;	

					break;
				case CKA_LABEL:
					obj_label = Tcl_NewStringObj(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_ID:
					/* Convert the ID into a readable string */
					obj_id = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
				case CKA_VALUE:
					if (!objectclass) {
						break;
					}

					obj_cert = Tcl_NewByteArrayObj(curr_attr->pValue, curr_attr->ulValueLen);

					break;
			}

			ckfree(curr_attr->pValue);
			curr_attr->pValue = NULL;
		}
/*LISSI*/
		if (type_cert == 0) {
			continue;
		}

		/* Add this certificate data to return list, if all found */
		if (obj_label == NULL || obj_id == NULL || obj_cert == NULL) {
			continue;
		}

		/* Create the current item list */
		curr_item_list = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_handle", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_handle);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_slotid", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_slotid);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_id", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_id);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_label", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_label);

		/* Call "::pki::x509::parse_cert" to parse the cert */
		parse_cert_cmd = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, parse_cert_cmd, Tcl_NewStringObj("::pki::x509::parse_cert", -1));
		Tcl_ListObjAppendElement(interp, parse_cert_cmd, obj_cert);

		tcl_rv = Tcl_EvalObjEx(interp, parse_cert_cmd, 0);
		if (tcl_rv != TCL_OK) {
			continue;
		}

		/* Add results of [parse_cert] to our return value */
		Tcl_ListObjAppendList(interp, curr_item_list, Tcl_GetObjResult(interp));

		/*
		 * Override the "type" so that [array set] returns our new
		 * type, but we can still parse through the list and figure
		 * out the real subordinate type
		 */
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("type", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11", -1));

		/* Add the current item to the return value list */
		Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);
	}

	/* Terminate search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	/* Return */
	Tcl_SetObjResult(interp, ret_list);

	return(TCL_OK);
}
/*LISSI*/
MODULE_SCOPE int tclpkcs11_list_certs_der(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid;
	long slotid_long;
	Tcl_Obj *obj_label, *obj_id, *obj_cert_der;
	Tcl_Obj *ret_list, *curr_item_list;
	int tcl_rv;
	int type_cert;
	CK_SLOT_ID slotid;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG ulObjectCount;
	static CK_OBJECT_CLASS     oclass_cert     = CKO_CERTIFICATE;
//	                           {CKA_ID, NULL, 0},
	CK_ATTRIBUTE cert_templ[] = {
	                           {CKA_CLASS, &oclass_cert, sizeof(oclass_cert)},
	};
	CK_ATTRIBUTE template[] = {
	                           {CKA_CLASS, NULL, 0},
	                           {CKA_LABEL, NULL, 0},
	                           {CKA_ID, NULL, 0},
	                           {CKA_VALUE, NULL, 0}
	}, *curr_attr;
	CK_ULONG curr_attr_idx;
	CK_OBJECT_CLASS *objectclass;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::listcertsder handle slot\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

//	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, NULL, 0);
	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session,  cert_templ, sizeof(cert_templ) / sizeof(cert_templ[0]));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	ret_list = Tcl_NewObj();
	while (1) {
		type_cert = 0;	
		chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &ulObjectCount);
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		if (ulObjectCount == 0) {
			break;
		}

		if (ulObjectCount != 1) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("FindObjects() returned a weird number of objects.", -1));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];
			if (curr_attr->pValue) {
				ckfree(curr_attr->pValue);
			}

			curr_attr->pValue = NULL;
			curr_attr->ulValueLen = 0;
		}

		/* Determine size of values to allocate */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
		if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
			chk_rv = CKR_OK;
		}

		if (chk_rv != CKR_OK) {
			/* Skip this object if we are not able to process it */
			continue;
		}

		/* Allocate values */
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];

			if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
				curr_attr->pValue = (void *) ckalloc(curr_attr->ulValueLen);
			}
		}

		/* Populate template values */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
		if (chk_rv != CKR_OK && chk_rv != CKR_ATTRIBUTE_SENSITIVE && chk_rv != CKR_ATTRIBUTE_TYPE_INVALID && chk_rv != CKR_BUFFER_TOO_SMALL) {
			/* Return an error if we are unable to process this entry due to unexpected errors */
			for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
				curr_attr = &template[curr_attr_idx];
				if (curr_attr->pValue) {
					ckfree(curr_attr->pValue);
				}
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		/* Extract certificate data */
		obj_label = NULL;
		obj_id = NULL;
		obj_cert_der = NULL;
		objectclass = NULL;
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];

			if (!curr_attr->pValue) {
				continue;
			}

			switch (curr_attr->type) {
				case CKA_CLASS:
					objectclass = (CK_OBJECT_CLASS *) curr_attr->pValue;
					if (*objectclass != CKO_CERTIFICATE) {
						continue;
					}
					type_cert = 1;
					break;
				case CKA_LABEL:
					obj_label = Tcl_NewStringObj(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_ID:
					/* Convert the ID into a readable string */
					obj_id = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
				case CKA_VALUE:
/*LISSI*/
//fprintf (stderr, "tclpkcs11_list_certs_der: LEN_VALUE=%lu\n", curr_attr->ulValueLen);
					if (!objectclass) {
						break;
					}

					/* Convert the DER_CERT into a readable string */
					obj_cert_der = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
			}

			ckfree(curr_attr->pValue);
			curr_attr->pValue = NULL;
		}
		if (type_cert == 0) {
			continue;
		}

		/* Add this certificate data to return list, if all found */
		if (obj_label == NULL || obj_id == NULL || obj_cert_der == NULL) {
			continue;
		}

		/* Create the current item list */
		curr_item_list = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_handle", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_handle);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_slotid", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_slotid);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_id", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_id);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_label", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_label);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("cert_der", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_cert_der);

		/*
		 * Override the "type" so that [array set] returns our new
		 * type, but we can still parse through the list and figure
		 * out the real subordinate type
		 */
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("type", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11", -1));

		/* Add the current item to the return value list */
		Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);
	}

	/* Terminate search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	/* Return */
	Tcl_SetObjResult(interp, ret_list);
//	Tcl_SetObjResult(interp, curr_item_list);

	return(TCL_OK);
}
static char *class_name[] = {
	"CKO_DATA",
	"CKO_CERTIFICATE",
	"CKO_PUBLIC_KEY",
	"CKO_PRIVATE_KEY",
	"CKO_SECRET_KEY",
	"CKO_HW_FEATURE",
	"CKO_DOMAIN_PARAMETERS",
	"CKO_VENDOR_DEFINED"
};
MODULE_SCOPE int tclpkcs11_list_objects(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    CK_BYTE *value = NULL;
    CK_ULONG value_len = 0;

	static CK_BBOOL ltrue = CK_TRUE;
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid;
	long slotid_long;
	Tcl_Obj *obj_label, *obj_id, *obj_object, *obj_value;
	Tcl_Obj *ret_list, *curr_item_list;
	int tcl_rv;
	CK_SLOT_ID slotid;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG ulObjectCount;
//	static CK_OBJECT_CLASS     oclass     = CKO_CERTIFICATE;
//	                           {CKA_ID, NULL, 0},
	char *objtype = NULL, *objdump = NULL;
        CK_UTF8CHAR label[2048];
        
	CK_OBJECT_CLASS oclass = 0;
	CK_BYTE ckaid[20];
	CK_BYTE *ckavalue;
	CK_ATTRIBUTE *attr_find_obj;

	CK_ATTRIBUTE attr_find[] = {
	    {CKA_TOKEN, &ltrue, sizeof(ltrue)},
	};
	CK_ATTRIBUTE attr_class[] = {
	    {CKA_CLASS, NULL, 0},
	};
	CK_ATTRIBUTE attr_label[] = {
	    {CKA_LABEL, NULL, 0},
	};
	CK_ATTRIBUTE attr_ckaid[] = {
	    {CKA_ID, NULL, 0},
	};
	CK_ATTRIBUTE attr_ckavalue[] = {
	    {CKA_VALUE, NULL, 0},
	};
	int count;
	
	CK_ATTRIBUTE attr_find_class[] = {
	    {CKA_TOKEN, &ltrue, sizeof(ltrue)},
	    {CKA_CLASS, &oclass, sizeof(oclass)},
	};
  
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc < 3 && objc > 5) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::listobjects handle slot [all|privkey|pubkey|cert|data] [value]\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];
	count = 1;
	attr_find_obj = attr_find;
	if (objc > 3) {
	    count = 2;
	    objtype = Tcl_GetString(objv[3]);
//fprintf(stderr, "LISTOBJECTS objtype=%s\n", objtype);
	    if (strcmp(objtype, "all") == 0) {
		attr_find_obj = attr_find;
		count = 1;
	    } else if (strcmp(objtype, "cert") == 0) {
		attr_find_obj = attr_find;
		oclass = CKO_CERTIFICATE;
		attr_find_obj = attr_find_class;
	    } else if (strcmp(objtype, "pubkey") == 0) {
		attr_find_obj = attr_find;
		oclass = CKO_PUBLIC_KEY;
		attr_find_obj = attr_find_class;
	    } else if (strcmp(objtype, "privkey") == 0) {
		attr_find_obj = attr_find;
		oclass = CKO_PRIVATE_KEY;
		attr_find_obj = attr_find_class;
	    } else if (strcmp(objtype, "data") == 0) {
		attr_find_obj = attr_find;
		oclass = CKO_DATA;
		attr_find_obj = attr_find_class;
	    } else {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("pki::pkcs11::listobjects handle slot [all|privkey|pubkey|cert|data] [value]\"", -1));
		return(TCL_ERROR);
	    }
	}
	if (objc > 4) {
	    objdump = Tcl_GetString(objv[4]);
	    if (strcmp(objdump, "value") != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("pki::pkcs11::listobjects handle slot [all|privkey|pubkey|cert|data] [value]\"", -1));
		return(TCL_ERROR);
	    }
	    if (strcmp(objtype, "privkey") == 0 && (strcmp(objdump, "value") == 0)) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("pki::pkcs11::listobjects: cannot value private key\"", -1));
		return(TCL_ERROR);
	    }
	    if (strcmp(objtype, "all") == 0 && (strcmp(objdump, "value") == 0)) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("pki::pkcs11::listobjects: cannot value private key\"", -1));
		return(TCL_ERROR);
	    }
//fprintf(stderr, "LISTOBJECTS objdump=%s\n", objdump);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session,  attr_find_obj, count);
//	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session,  attr_find_obj, sizeof(attr_find) / sizeof(CK_ATTRIBUTE));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	ret_list = Tcl_NewObj();
	while (1) {
		char *name = NULL;
		memset(label, 0, sizeof(label));
		attr_class[0].pValue = &oclass;
		attr_class[0].ulValueLen = sizeof(oclass);
		attr_label[0].pValue = label;
		attr_label[0].ulValueLen = sizeof(label);
		attr_ckaid[0].pValue = ckaid;
		attr_ckaid[0].ulValueLen = sizeof(ckaid);


		chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &ulObjectCount);
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		if (ulObjectCount == 0) {
			break;
		}

		if (ulObjectCount != 1) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("FindObjects() returned a weird number of objects.", -1));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}
//////////////////////
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_class, sizeof(attr_class)/sizeof(CK_ATTRIBUTE));
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetAttributeValue CKA_CLASS for CKA_OBJECT_CLASS.", -1));
			handle->pkcs11->C_FindObjectsFinal(handle->session);
			return(TCL_ERROR);
		}
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_label, sizeof(attr_label)/sizeof(CK_ATTRIBUTE));
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetAttributeValue CKA_LABEL for CKA_OBJECT_CLASS.", -1));
			handle->pkcs11->C_FindObjectsFinal(handle->session);
			return(TCL_ERROR);
		}
		if (oclass >= CKO_VENDOR_DEFINED) {
			name = class_name[7];
		} else {
			name = class_name[oclass];
		}
		obj_object = Tcl_NewStringObj(name, strlen(name));
//fprintf(stderr, "%s\n", name);
//fprintf(stderr, "\t label: '%s'\n", label);
		obj_label = Tcl_NewStringObj((const char *)label, attr_label[0].ulValueLen);

		if (oclass == CKO_CERTIFICATE || oclass == CKO_PUBLIC_KEY || oclass == CKO_PRIVATE_KEY) {
		    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_ckaid, sizeof(attr_ckaid)/sizeof(CK_ATTRIBUTE));
		    if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetAttributeValue CKA_ID for CKA_OBJECT_CLASS.", -1));
			handle->pkcs11->C_FindObjectsFinal(handle->session);
			return(TCL_ERROR);
		    }
					// Convert the ID into a readable string 
		    obj_id = tclpkcs11_bytearray_to_string(ckaid, sizeof(ckaid));
		} else {
		    obj_id = Tcl_NewStringObj("NONE", -1);
		}
		if (objc == 5) {
		    attr_ckavalue[0].pValue = NULL;
		    attr_ckavalue[0].ulValueLen = 0;
		    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_ckavalue, sizeof(attr_ckavalue)/sizeof(CK_ATTRIBUTE));
		    if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetAttributeValue CKA_VALUE for CKA_OBJECT_CLASS.", -1));
			handle->pkcs11->C_FindObjectsFinal(handle->session);
			return(TCL_ERROR);
		    }
//fprintf(stderr, "LEN=%i\n", attr_ckavalue[0].ulValueLen);
		    attr_ckavalue[0].pValue = ckalloc(attr_ckavalue[0].ulValueLen);
		    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_ckavalue, sizeof(attr_ckavalue)/sizeof(CK_ATTRIBUTE));
		    if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetAttributeValue CKA_VALUE for CKA_OBJECT_CLASS.", -1));
			handle->pkcs11->C_FindObjectsFinal(handle->session);
			return(TCL_ERROR);
		    }
		    obj_value = tclpkcs11_bytearray_to_string(attr_ckavalue[0].pValue, attr_ckavalue[0].ulValueLen);
		    ckfree(attr_ckavalue[0].pValue);
		}
		/* Create the current item list */
		curr_item_list = Tcl_NewObj();
//		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_object", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_object);

//		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_label", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_label);

		if (oclass == CKO_CERTIFICATE || oclass == CKO_PUBLIC_KEY || oclass == CKO_PRIVATE_KEY) {
//		    Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_id", -1));
		    Tcl_ListObjAppendElement(interp, curr_item_list, obj_id);
		}
		if (objc == 5) {
		    Tcl_ListObjAppendElement(interp, curr_item_list, obj_value);
		}
		/* Add the current item to the return value list */
		Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);
	}

	/* Terminate search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	/* Return */
	Tcl_SetObjResult(interp, ret_list);
//	Tcl_SetObjResult(interp, curr_item_list);

	return(TCL_OK);
}


MODULE_SCOPE int tclpkcs11_login(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid, *tcl_password;
	long slotid_long;
	char *password;
	int password_len;
	int tcl_rv;

	CK_SLOT_ID slotid;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 4) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::login handle slot password\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];
	tcl_password = objv[3];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	password = Tcl_GetStringFromObj(tcl_password, &password_len);

	chk_rv = handle->pkcs11->C_Login(handle->session, CKU_USER, (CK_UTF8CHAR_PTR) password, password_len);
	switch (chk_rv) {
		case CKR_OK:
		case CKR_USER_ALREADY_LOGGED_IN:
			Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));

			break;
		case CKR_PIN_INCORRECT:
			Tcl_SetObjResult(interp, Tcl_NewBooleanObj(0));

			break;
		default:
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
	}

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_logout(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid;
	long slotid_long;
	int tcl_rv;

	CK_SLOT_ID slotid;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::login handle slot\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_Logout(handle->session);
	if (chk_rv != CKR_OK) {
		if (chk_rv == CKR_DEVICE_REMOVED) {
			handle->session_active = 0;

			handle->pkcs11->C_CloseSession(handle->session);
		} else {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}
	}

	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));

	return(TCL_OK);
}
/*LISSI*/
MODULE_SCOPE int tclpkcs11_listmechs(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid;
	long slotid_long;
	int tcl_rv;
	CK_MECHANISM_TYPE_PTR MechanismList = NULL;  // Head to Mechanism list
	CK_ULONG       MechanismCount = 0;  // Number of supported mechanisms
	unsigned int   lcv2;           // Loop Control Variables
	CK_CHAR *name;
	CK_SLOT_ID slotid;
	Tcl_Obj *curr_item_list;
	char bufmech[256];


	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::mechanism handle slot \"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;
	tcl_rv = handle->pkcs11->C_GetMechanismList(slotid, NULL, &MechanismCount);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

    /* Allocate enough memory to store all the supported mechanisms */
	MechanismList = (CK_MECHANISM_TYPE_PTR) malloc(MechanismCount *sizeof(CK_MECHANISM_TYPE));

    /* This time get the mechanism list */
	tcl_rv = handle->pkcs11->C_GetMechanismList(slotid, MechanismList, &MechanismCount);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

    /* For each Mechanism in the List */
	curr_item_list = Tcl_NewObj();
	for (lcv2 = 0; lcv2 < MechanismCount; lcv2++){
      /* Get the Mechanism Info and display it */
	    name = (CK_CHAR *)get_mechanism_name(MechanismList[lcv2]);
	    if (name) {
		sprintf((char *)bufmech, "%s (0x%lX)", name, MechanismList[lcv2]);
	    } else {
		sprintf((char *)bufmech, "0x%lX (0x%lX)", MechanismList[lcv2], MechanismList[lcv2]);
	    }
	    Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj(bufmech, -1));
	}
    /* Free the memory we allocated for the mechanism list */
	free (MechanismList);

	Tcl_SetObjResult(interp, curr_item_list);
	return(TCL_OK);
}
MODULE_SCOPE int tclpkcs11_perform_pki_pkinfo(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	CK_ULONG *ulattr;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL, *tcl_objid = NULL;
	unsigned long tcl_strtobytearray_rv;
	long slotid_long;
	CK_SLOT_ID slotid;
	CK_RV chk_rv;
	Tcl_HashEntry *tcl_handle_entry;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG foundObjs;
	CK_OBJECT_CLASS objectclass_pk;
	CK_ULONG curr_attr_idx;
	Tcl_Obj *obj_label, *obj_id, *obj_key_der, *obj_gostr3411, *obj_gostr3410, *obj_gost28147, *obj_key_type;
	CK_OBJECT_CLASS *objectclass;
	Tcl_Obj *curr_item_list;

	CK_ATTRIBUTE template[] = {
	                           {CKA_ID, NULL, 0},
	                           {CKA_CLASS, NULL, 0},
	};
	CK_ATTRIBUTE templ_pk[] = {
	                           {CKA_CLASS, NULL, 0},
	                           {CKA_LABEL, NULL, 0},
	                           {CKA_ID, NULL, 0},
	                           {CKA_VALUE, NULL, 0},
	                           {CKA_GOSTR3410PARAMS, NULL, 0},
	                           {CKA_GOSTR3411PARAMS, NULL, 0},
	                           {CKA_GOST28147PARAMS, NULL, 0},
	                           {CKA_KEY_TYPE, NULL, 0}
	}, *curr_attr;

	int tcl_rv;
//fprintf(stderr, "tclpkcs11_perform_pki_pkinfo objc=%i\n", objc);
	if (objc != 4) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::pkinfo handle slot pkcs11_id\"", -1));

		return(TCL_ERROR);
	}
	tcl_handle = objv[1];
	tcl_slotid = objv[2];
	tcl_objid = objv[3];
	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	/*
	 * Find the PKCS#11 object ID that cooresponds to this certificate's
	 * private key
	 */
	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* CKA_ID */
	template[0].pValue = ckalloc(Tcl_GetCharLength(tcl_objid) / 2);
	tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_objid, template[0].pValue, Tcl_GetCharLength(tcl_objid) / 2);
	template[0].ulValueLen = tcl_strtobytearray_rv;

	/* CKA_CLASS */
	objectclass_pk = CKO_PUBLIC_KEY;
	template[1].pValue = &objectclass_pk;
	template[1].ulValueLen = sizeof(objectclass_pk);

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	}

	/* Terminate Search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	if (foundObjs < 1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("PKCS11_ERROR MAYBE_LOGIN", -1));

		return(TCL_ERROR);
	}

//fprintf(stderr, "tclpkcs11_perform_pki_pkinfo=PUB_KEY FIND=%lu\n", foundObjs);
	if (foundObjs != 1) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("FindObjects() from pkinfo returned a weird number of objects.", -1));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
	}
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
			curr_attr = &templ_pk[curr_attr_idx];
			if (curr_attr->pValue) {
				ckfree(curr_attr->pValue);
			}

			curr_attr->pValue = NULL;
			curr_attr->ulValueLen = 0;
		}

		/* Determine size of values to allocate */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, templ_pk, sizeof(templ_pk) / sizeof(templ_pk[0]));
		if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
			chk_rv = CKR_OK;
		}

		if (chk_rv != CKR_OK) {
			/* Skip this object if we are not able to process it */
			return(TCL_ERROR);
		}

		/* Allocate values */
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
			curr_attr = &templ_pk[curr_attr_idx];

			if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
				curr_attr->pValue = (void *) ckalloc(curr_attr->ulValueLen);
			}
		}

		/* Populate template values */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, templ_pk, sizeof(templ_pk) / sizeof(templ_pk[0]));
		if (chk_rv != CKR_OK && chk_rv != CKR_ATTRIBUTE_SENSITIVE && chk_rv != CKR_ATTRIBUTE_TYPE_INVALID && chk_rv != CKR_BUFFER_TOO_SMALL) {
			/* Return an error if we are unable to process this entry due to unexpected errors */
			for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
				curr_attr = &templ_pk[curr_attr_idx];
				if (curr_attr->pValue) {
					ckfree(curr_attr->pValue);
				}
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}
	
//////////////////////////////////////////////
		/* Extract publickey data */
		obj_label = NULL;
		obj_id = NULL;
		obj_key_der = NULL;
		objectclass = NULL;
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
			curr_attr = &templ_pk[curr_attr_idx];

			if (!curr_attr->pValue) {
				continue;
			}

			switch (curr_attr->type) {
				case CKA_CLASS:
					objectclass = (CK_OBJECT_CLASS *) curr_attr->pValue;
					if (*objectclass != CKO_PUBLIC_KEY) {
						continue;
					}
					break;
				case CKA_LABEL:
					obj_label = Tcl_NewStringObj(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_ID:
					/* Convert the ID into a readable string */
					obj_id = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
				case CKA_VALUE:
					if (!objectclass) {
						break;
					}
					/* Convert the DER_KEY into a readable string */
					obj_key_der = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
				case CKA_GOSTR3411PARAMS:
					obj_gostr3411 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_GOSTR3410PARAMS:
					obj_gostr3410 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_GOST28147PARAMS:
					obj_gost28147 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_KEY_TYPE:
					ulattr = curr_attr->pValue;
					if (*ulattr == CKK_GOSTR3410) {
					    if (!strstr(Tcl_GetString(obj_gostr3411), "06082a850307")) {
						obj_key_type = Tcl_NewStringObj("1 2 643 2 2 19", -1);
					    } else {
						obj_key_type = Tcl_NewStringObj("1 2 643 7 1 1 1 1", -1);
					    }
//fprintf(stderr, "tclpkcs11_perform_pki_pkinfo CKK_GOSTR3410\n");
					} else if (*ulattr == CKK_GOSTR3410_512) {
						obj_key_type = Tcl_NewStringObj("1 2 643 7 1 1 1 2", -1);
//fprintf(stderr, "tclpkcs11_perform_pki_pkinfo CKK_GOSTR3410_512=%s\n", Tcl_GetString(obj_gostr3411));
					} else {
fprintf(stderr, "tclpkcs11_perform_pki_pkinfo CKK_GOSTR ERROR\n");
					}
					break;
			}

			ckfree(curr_attr->pValue);
			curr_attr->pValue = NULL;
		}

		/* Add this certificate data to return list, if all found */
		if (obj_label == NULL || obj_id == NULL || obj_key_der == NULL) {
//			continue;
		}

		/* Create the current item list */
		curr_item_list = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_handle", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_handle);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_slotid", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_slotid);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_id", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_id);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_label", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_label);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pubkey", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_key_der);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pubkey_algo", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_key_type);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("gostR3410params", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_gostr3410);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("gostR3411params", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_gostr3411);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("gost28147params", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_gost28147);

		/*
		 * Override the "type" so that [array set] returns our new
		 * type, but we can still parse through the list and figure
		 * out the real subordinate type
		 */
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("type", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11", -1));

		/* Add the current item to the return value list */
	/* Return */
	Tcl_SetObjResult(interp, curr_item_list);
	return(TCL_OK);
}

/*LISSI*/
MODULE_SCOPE int tclpkcs11_perform_pki_sign(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	unsigned char *input, resultbuf[1024];
	char *ckm_mech;
	int input_len;
	CK_ULONG resultbuf_len;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL, *tcl_objid = NULL;
	unsigned long tcl_strtobytearray_rv;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_mode, *tcl_input;
	Tcl_Obj *tcl_result;
	long slotid_long;
	int tcl_keylist_llength, idx;
	CK_SLOT_ID slotid;
	CK_MECHANISM     mechanism_desc = { CKM_GOSTR3410, NULL, 0 };
	CK_MECHANISM     mechanism_desc_512 = { CKM_GOSTR3410_512, NULL, 0 };
	CK_MECHANISM_PTR mechanism;
	CK_RV chk_rv;
	Tcl_HashEntry *tcl_handle_entry;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG foundObjs;
	CK_OBJECT_CLASS objectclass_pk;

	CK_ATTRIBUTE template[] = {
	                           {CKA_ID, NULL, 0},
	                           {CKA_CLASS, NULL, 0},
	};
	int tcl_rv;

	tcl_mode = objv[1];
	tcl_input = objv[2];
	tcl_keylist = objv[3];
	/* HASH for SIGN */
	input = ckalloc(Tcl_GetCharLength(tcl_input) / 2);
	input_len = tclpkcs11_string_to_bytearray(tcl_input, input, Tcl_GetCharLength(tcl_input) / 2);

	ckm_mech = Tcl_GetString(tcl_mode);
//fprintf(stderr, "tclpkcs11_perform_pki_sign input_len=%i, nickcert=%s\n", input_len, ckm_mech);
	if (!memcmp("CKM_GOSTR3410_512", ckm_mech, 17)) {
	    mechanism = &mechanism_desc_512;
	    resultbuf_len = 128;
	    if (input_len != 64) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::sign CKM_GOSTR3410_512 input\" - bad len hash", -1));
		return(TCL_ERROR);
	    }
	} else 	if (!memcmp("CKM_GOSTR3410", ckm_mech, 13)) {
	    mechanism = &mechanism_desc;
	    resultbuf_len = 64;
	    if (input_len != 32) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::sign CKM_GOSTR3410 input\" - bad len hash", -1));
		return(TCL_ERROR);
	    }
	} else {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::sign CKM_GOSTR3410|CKM_GOSTR3410_512 input\" - bad sign", -1));
		return(TCL_ERROR);
	}


	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));

		return(TCL_ERROR);
	}
	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];
//fprintf(stderr,"SIGN h_slotid=%s\n", Tcl_GetString(tcl_keylist_key));

		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_id") == 0) {
			tcl_objid = tcl_keylist_val;
			continue;
		}
	}
	if (!tcl_handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_handle\" in keylist", -1));

		return(TCL_ERROR);
	}

	if (!tcl_slotid) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_slotid\" in keylist", -1));

		return(TCL_ERROR);
	}

	if (!tcl_objid) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_id\" in keylist", -1));

		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	/*
	 * Find the PKCS#11 object ID that cooresponds to this certificate's
	 * private key
	 */
	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* CKA_ID */
	template[0].pValue = ckalloc(Tcl_GetCharLength(tcl_objid) / 2);
	tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_objid, template[0].pValue, Tcl_GetCharLength(tcl_objid) / 2);
	template[0].ulValueLen = tcl_strtobytearray_rv;

	/* CKA_CLASS */
	objectclass_pk = CKO_PRIVATE_KEY;
	template[1].pValue = &objectclass_pk;
	template[1].ulValueLen = sizeof(objectclass_pk);

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	}

	/* Terminate Search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	if (foundObjs < 1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("PKCS11_ERROR MAYBE_LOGIN", -1));

		return(TCL_ERROR);
	}

//fprintf(stderr, "tclpkcs11_perform_pki_sign=PRIV_KEY FIND\n");
	chk_rv = handle->pkcs11->C_SignInit(handle->session, mechanism, hObject);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}

//fprintf(stderr, "tclpkcs11_perform_pki_sign Init OK\n");
	chk_rv = handle->pkcs11->C_Sign(handle->session, input, input_len, resultbuf, &resultbuf_len);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}

	tcl_result = tclpkcs11_bytearray_to_string(resultbuf, resultbuf_len);

	Tcl_SetObjResult(interp, tcl_result);
//fprintf(stderr,"tclpkcs11_perform_pki_sign OK len=%lu\n", resultbuf_len);

	return(TCL_OK);
}

/*LISSI*/
MODULE_SCOPE int tclpkcs11_perform_pki_keypair(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	char *algokey, *param;
	unsigned char *asn, *asn1, *asn2;
	CK_ULONG *ulattr;
	int i;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_key, *tcl_input;
	long slotid_long;
	int tcl_keylist_llength, idx;
	CK_SLOT_ID slotid;
	CK_MECHANISM     mechanism_desc_512 = { CKM_GOSTR3410_512_KEY_PAIR_GEN, NULL, 0 };
	CK_MECHANISM     mechanism_desc_256 = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL, 0 };
	CK_MECHANISM_PTR mechanism_gen;
	CK_RV chk_rv;
	Tcl_HashEntry *tcl_handle_entry;
	CK_ULONG curr_attr_idx;
	Tcl_Obj *obj_label, *obj_id, *obj_key_der, *obj_gostr3411, *obj_gostr3410, *obj_key_type, *obj_key_type_oid;
	Tcl_Obj *obj_gost28147;
	CK_OBJECT_CLASS *objectclass;
	Tcl_Obj *curr_item_list;
    static CK_BBOOL        ltrue       = CK_TRUE;
    static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
    static CK_OBJECT_CLASS oclass_priv = CKO_PRIVATE_KEY;
    static CK_BYTE         gost28147params_Z[] = {
        0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01
    };
/* GOST R 34.10-2001 CryptoPro parameter set OIDs*/
    static CK_BYTE ecc_A_oid[]    = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01};
    static CK_BYTE ecc_B_oid[]    = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02};
    static CK_BYTE ecc_C_oid[]    = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03};
    static CK_BYTE ecc_XchA_oid[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00};
    static CK_BYTE ecc_XchB_oid[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01};
/*LISSI 2012*/
    static CK_BYTE gost3411_2012_256[] = {0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};
    static CK_BYTE gost3411_2012_512[] = {0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03};
/*1.2.643.7.1.1.2.2	id-tc26-gost3411-2012-256	алгоритм хэширования ГОСТ Р 34.11-2012 с длиной 256*/
/*CONST_OID gost3411_2012_256[] = {0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};*/
/*1.2.643.7.1.1.2.3	id-tc26-gost3411-2012-512	алгоритм хэширования ГОСТ Р 34.11-2012 с длиной 512*/
/*CONST_OID gost3411_2012_512[] = {0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03};*/
    static CK_BYTE tc26_decc_A_der_oid[] = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01};
    static CK_BYTE tc26_decc_B_der_oid[] = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x02};

    CK_OBJECT_HANDLE       pub_key            = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE       priv_key           = CK_INVALID_HANDLE;

    CK_ATTRIBUTE       pub_template[] = {
        { CKA_CLASS,           &oclass_pub, sizeof(oclass_pub) },
        { CKA_TOKEN,           &ltrue,      sizeof(ltrue)      },
        { CKA_GOSTR3410PARAMS,	NULL, 0 },
        { CKA_GOSTR3411PARAMS,  NULL, 0 },
        { CKA_VERIFY,          &ltrue,      sizeof(CK_BBOOL)   },
        { CKA_GOST28147PARAMS, gost28147params_Z, sizeof(gost28147params_Z) },
    };
    CK_ATTRIBUTE       priv_template[] = {
        { CKA_CLASS,   &oclass_priv, sizeof(oclass_priv) },
        { CKA_TOKEN,   &ltrue,       sizeof(ltrue)       },
        { CKA_PRIVATE, &ltrue,       sizeof(ltrue)       },
        { CKA_SIGN,    &ltrue,       sizeof(CK_BBOOL)    },
    };
    CK_ATTRIBUTE templ_pk[] = {
	                           {CKA_CLASS, NULL, 0},
	                           {CKA_LABEL, NULL, 0},
	                           {CKA_ID, NULL, 0},
	                           {CKA_VALUE, NULL, 0},
	                           {CKA_GOSTR3410PARAMS, NULL, 0},
	                           {CKA_GOSTR3411PARAMS, NULL, 0},
	                           {CKA_GOST28147PARAMS, NULL, 0},
	                           {CKA_KEY_TYPE, NULL, 0}
    }, *curr_attr;
	int tcl_rv;

	tcl_key = objv[1];
	tcl_input = objv[2];
	tcl_keylist = objv[3];
	if (objc != 4) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::keypair g12_256|g12_512 param_sign list_for_token\"", -1));
		return(TCL_ERROR);
	}

	param = Tcl_GetString(tcl_input);
	algokey = Tcl_GetString(tcl_key);
//fprintf(stderr, "tclpkcs11_perform_pki_keypair objc=%d, algokey=%s, param=%s\n",  objc, algokey, param);
	if (!memcmp("g12_256", algokey, 7)) {
	    mechanism_gen = &mechanism_desc_256;
	    pub_template[2].pValue = ecc_A_oid;
	    pub_template[2].ulValueLen = sizeof(ecc_A_oid);
	    pub_template[3].pValue =gost3411_2012_256; 
	    pub_template[3].ulValueLen = sizeof(gost3411_2012_256);
	} else if (!memcmp("g12_512", algokey, 7)) {
	    mechanism_gen = &mechanism_desc_512;
	    pub_template[2].pValue = tc26_decc_A_der_oid;
	    pub_template[2].ulValueLen = sizeof(tc26_decc_A_der_oid);
	    pub_template[3].pValue =gost3411_2012_512; 
	    pub_template[3].ulValueLen = sizeof(gost3411_2012_512);
	} else {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::keypair g12_256|g12512 param_sign list_for_token\" - bad type key", -1));
		return(TCL_ERROR);
	}
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));

		return(TCL_ERROR);
	}
	i = 0;
	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];

		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;
//fprintf(stderr,"KeyPair H=%s\n", Tcl_GetString(tcl_handle));
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;
//fprintf(stderr,"KeyPair Slot=%s\n", Tcl_GetString(tcl_slotid));
			i++;
			continue;
		}
	}
	if (i != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle or slot", -1));
		return(TCL_ERROR);
	}
	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	slotid_long = atol(Tcl_GetString(tcl_slotid));
	slotid = slotid_long;

//fprintf(stderr,"tclpkcs11_perform_pki_keypair slotid=%lu\n", slotid);
	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}
//fprintf(stderr,"tclpkcs11_perform_pki_keypair SESSION OK\n");
    chk_rv = handle->pkcs11->C_GenerateKeyPair(handle->session, mechanism_gen,
                                  pub_template, sizeof(pub_template) / sizeof(CK_ATTRIBUTE),
                                  priv_template, sizeof(priv_template) / sizeof(CK_ATTRIBUTE),
                                  &pub_key, &priv_key);
    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
    }

//fprintf(stderr,"tclpkcs11_perform_pki_keypair OK len=\n");
////// Очищаем templ_pk ////////////////////////////
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
			curr_attr = &templ_pk[curr_attr_idx];
			if (curr_attr->pValue) {
				ckfree(curr_attr->pValue);
			}

			curr_attr->pValue = NULL;
			curr_attr->ulValueLen = 0;
		}

		/* Determine size of values to allocate */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, pub_key, templ_pk, sizeof(templ_pk) / sizeof(templ_pk[0]));
		if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
			chk_rv = CKR_OK;
		}

		if (chk_rv != CKR_OK) {
			/* Skip this object if we are not able to process it */
			return(TCL_ERROR);
		}

		/* Allocate values */
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
			curr_attr = &templ_pk[curr_attr_idx];

			if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
				curr_attr->pValue = (void *) ckalloc(curr_attr->ulValueLen);
			}
		}

		/* Populate template values */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, pub_key, templ_pk, sizeof(templ_pk) / sizeof(templ_pk[0]));
		if (chk_rv != CKR_OK && chk_rv != CKR_ATTRIBUTE_SENSITIVE && chk_rv != CKR_ATTRIBUTE_TYPE_INVALID && chk_rv != CKR_BUFFER_TOO_SMALL) {
			/* Return an error if we are unable to process this entry due to unexpected errors */
			for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
				curr_attr = &templ_pk[curr_attr_idx];
				if (curr_attr->pValue) {
					ckfree(curr_attr->pValue);
				}
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}
	
//////////////////////////////////////////////
		/* Extract publickey data */
		obj_label = NULL;
		obj_id = NULL;
		obj_key_der = NULL;
		objectclass = NULL;
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
			curr_attr = &templ_pk[curr_attr_idx];

			if (!curr_attr->pValue) {
				continue;
			}

			switch (curr_attr->type) {
				case CKA_CLASS:
					objectclass = (CK_OBJECT_CLASS *) curr_attr->pValue;
					if (*objectclass != CKO_PUBLIC_KEY) {
						continue;
					}
					break;
				case CKA_LABEL:
					obj_label = Tcl_NewStringObj(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_ID:
					/* Convert the ID into a readable string */
					obj_id = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
				case CKA_VALUE:
					if (!objectclass) {
						break;
					}
					/* Convert the DER_KEY into a readable string */
					obj_key_der = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
				case CKA_GOSTR3411PARAMS:
					obj_gostr3411 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_GOSTR3410PARAMS:
					obj_gostr3410 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_GOST28147PARAMS:
					obj_gost28147 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_KEY_TYPE:
					ulattr = curr_attr->pValue;
					if (*ulattr == CKK_GOSTR3410) {
					    if (!strstr(Tcl_GetString(obj_gostr3411), "06082a850307")) {
						obj_key_type_oid = Tcl_NewStringObj("1 2 643 2 2 19", -1);
						obj_key_type = tclpkcs11_bytearray_to_string((const unsigned char *)"\x06\x06\x2a\x85\x03\x02\x02\x13", 8);
					    } else {
						obj_key_type_oid = Tcl_NewStringObj("1 2 643 7 1 1 1 1", -1);
						obj_key_type = tclpkcs11_bytearray_to_string((const unsigned char *)"\x06\x08\x2a\x85\x03\x07\x01\x01\x01\x01", 10);
					    }
//fprintf(stderr, "tclpkcs11_perform_pki_keypair CKK_GOSTR3410\n");
					} else if (*ulattr == CKK_GOSTR3410_512) {
						obj_key_type_oid = Tcl_NewStringObj("1 2 643 7 1 1 1 2", -1);
						obj_key_type = tclpkcs11_bytearray_to_string((const unsigned char *)"\x06\x08\x2a\x85\x03\x07\x01\x01\x01\x02", 10);
//fprintf(stderr, "tclpkcs11_perform_pki_keypair CKK_GOSTR3410_512=%s\n", Tcl_GetString(obj_gostr3411));
					} else {
fprintf(stderr, "tclpkcs11_perform_pki_keypair CKK_GOSTR ERROR\n");
					}
					break;
			}

			ckfree(curr_attr->pValue);
			curr_attr->pValue = NULL;
		}

		/* Add this certificate data to return list, if all found */
		if (obj_label == NULL || obj_id == NULL || obj_key_der == NULL) {
//			continue;
		}

		/* Create the current item list */
		curr_item_list = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_handle", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_handle);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_slotid", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_slotid);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_id", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_id);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_label", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_label);
////pubkeyinfo
		asn = wrap_for_asn1('\x03',  "00", (asn1 = wrap_for_asn1('\x04',"", (unsigned char *)Tcl_GetString(obj_key_der))));
		free(asn1);
/*
		asn2 = malloc(strlen((const char*)Tcl_GetString(obj_gostr3410)) + strlen((const char*)Tcl_GetString(obj_gostr3411)) + 1);
		strcpy((char*)asn2, (const char*)Tcl_GetString(obj_gostr3410));
		strcat((char*)asn2, (const char*)Tcl_GetString(obj_gostr3411));
		asn1 = wrap_for_asn1('\x30',"", asn2);
		free(asn2);
*/
		asn1 = wrap_for_asn1('\x30', (char*)Tcl_GetString(obj_gostr3410), (unsigned char*)Tcl_GetString(obj_gostr3411));


		asn2 = malloc(strlen((const char*)Tcl_GetString(obj_key_type)) + strlen((const char*)asn1) + 1);
		strcpy((char*)asn2, (const char*)Tcl_GetString(obj_key_type));
		strcat((char*)asn2, (const char*)asn1);
		free(asn1);
		asn1 = wrap_for_asn1('\x30',  "", asn2);
		free(asn2);
		asn2 = malloc(strlen((const char*)asn) + strlen((const char*)asn1) + 1);
		strcpy((char*)asn2, (const char*)asn1);
		strcat((char*)asn2, (const char*)asn);
		free(asn1); free(asn);


		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pubkey", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_key_der);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pubkey_algo", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_key_type_oid);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pubkeyinfo", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj((const char *)asn2, -1));
		free(asn2);
		/*
		 * Override the "type" so that [array set] returns our new
		 * type, but we can still parse through the list and figure
		 * out the real subordinate type
		 */
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("type", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11", -1));

		/* Add the current item to the return value list */
	/* Return */
	Tcl_SetObjResult(interp, curr_item_list);
//fprintf(stderr, "tclpkcs11_perform_pki_keypair OK\n");
	return(TCL_OK);
}

/*LISSI*/
MODULE_SCOPE int tclpkcs11_perform_pki_dgst(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    GOSTR3411_2012_CTX ctx;
    unsigned char digest[64];
    int rc = 0;

	unsigned char *input;
	char *algohash;
	int input_len;
	Tcl_Obj *tcl_mode, *tcl_input;
	Tcl_Obj *tcl_result;
	int lenhash;

	tcl_mode = objv[1];
	tcl_input = objv[2];
	input = Tcl_GetByteArrayFromObj(tcl_input, &input_len);
	algohash = Tcl_GetString(tcl_mode);
//fprintf(stderr, "tclpkcs11_perform_pki_dgst objc=%d, algohash=%s\n",  objc,algohash);
//fprintf(stderr, "tclpkcs11_perform_pki_dgst=%i, objc=%s\n", input_len, input);
	if (!memcmp("stribog256", algohash, 10)) {
	    lenhash = 32;
	} else if (!memcmp("stribog512", algohash, 10)) {
	    lenhash = 64;
	} else {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::dgst stribog256|stribog512 input\" - bad digest", -1));
		return(TCL_ERROR);
	}
	rc = GOSTR3411_2012_Init(&ctx, lenhash);
	if (rc != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::dgst stribog256|stribog512 input\" - bad GOSTR3411_2012_Init stribog", -1));
		return(TCL_ERROR);
	}
	rc = GOSTR3411_2012_Update(&ctx, input, input_len); 
	if (rc != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::dgst stribog256|stribog512 input\" - GOSTR3411_2012_Update failed", -1));
		return(TCL_ERROR);
	}
	rc = GOSTR3411_2012_Final(&ctx, digest);
	if (rc != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::dgst stribog256|stribog512 input\" - GOSTR3411_2012_Final failed", -1));
		return(TCL_ERROR);
	}
	/* Convert the ID into a readable string */
	tcl_result = tclpkcs11_bytearray_to_string(digest, lenhash);

	Tcl_SetObjResult(interp, tcl_result);
//fprintf(stderr,"tclpkcs11_perform_pki_digest OK len=%lu\n", lenhash);

	return(TCL_OK);
}
MODULE_SCOPE int tclpkcs11_perform_pki_digest(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	unsigned char *input, resultbuf[1024];
	char *algohash;
	int input_len;
	int i;
	CK_ULONG resultbuf_len;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_mode, *tcl_input;
	Tcl_Obj *tcl_result;
	long slotid_long;
	int tcl_keylist_llength, idx;
	CK_SLOT_ID slotid;
	CK_MECHANISM     mechanism_desc = { CKM_GOSTR3411, NULL, 0 };
	CK_MECHANISM     mechanism_desc_512 = { CKM_GOSTR3411_12_512, NULL, 0 };
	CK_MECHANISM     mechanism_desc_256 = { CKM_GOSTR3411_12_256, NULL, 0 };
	CK_MECHANISM     mechanism_desc_sha1 = { CKM_SHA_1, NULL, 0 };
	CK_MECHANISM_PTR mechanism;
	CK_RV chk_rv;
	Tcl_HashEntry *tcl_handle_entry;
	int tcl_rv;

	tcl_mode = objv[1];
	tcl_input = objv[2];
	tcl_keylist = objv[3];
	input = Tcl_GetByteArrayFromObj(tcl_input, &input_len);
	algohash = Tcl_GetString(tcl_mode);
//fprintf(stderr, "tclpkcs11_perform_pki_digest objc=%d, algohash=%s\n",  objc,algohash);
//fprintf(stderr, "tclpkcs11_perform_pki_digest=%i, objc=%s\n", input_len, input);
	if (!memcmp("stribog256", algohash, 10)) {
	    mechanism = &mechanism_desc_256;
	} else if (!memcmp("stribog512", algohash, 10)) {
	    mechanism = &mechanism_desc_512;
	} else if (!memcmp("gostr3411", algohash, 9)) {
	    mechanism = &mechanism_desc;
	} else if (!memcmp("sha1", algohash, 4)) {
	    mechanism = &mechanism_desc_sha1;
	} else {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::digest stribog256|stribog512|gostr3411|sha1 input\" - bad digest", -1));
		return(TCL_ERROR);
	}
//fprintf(stderr, "tclpkcs11_perform_pki_digest=%i, hash=%s\n", input_len, algohash);
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));

		return(TCL_ERROR);
	}
	i = 0;
	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];
//fprintf(stderr,"Digest h_slotid=%s\n", Tcl_GetString(tcl_keylist_key));

		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;
			i++;
			continue;
		}
	}
	if (i != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle or slot", -1));
		return(TCL_ERROR);
	}
	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	slotid_long = atol(Tcl_GetString(tcl_slotid));
	slotid = slotid_long;

//fprintf(stderr,"tclpkcs11_perform_pki_digest Digest slotid=%lu\n", slotid);
	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}
//fprintf(stderr,"tclpkcs11_perform_pki_digest SESSION OK\n");
	chk_rv = handle->pkcs11->C_DigestInit(handle->session, mechanism);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}
	
	resultbuf_len = 128;
	chk_rv = handle->pkcs11->C_Digest(handle->session, input, input_len, resultbuf, &resultbuf_len);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}

	/* Convert the ID into a readable string */
	tcl_result = tclpkcs11_bytearray_to_string(resultbuf, resultbuf_len);

	Tcl_SetObjResult(interp, tcl_result);
//fprintf(stderr,"tclpkcs11_perform_pki_digest OK len=%lu\n", resultbuf_len);

	return(TCL_OK);
}
MODULE_SCOPE int tclpkcs11_perform_pki_pubkeyinfo(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    CK_BYTE *cert_der;
    CK_BYTE cka_id[20];
    Tcl_Obj *curr_item_list;
    int seek;
    unsigned char *pks;
    CK_MECHANISM     mechanism_desc_sha1 = { CKM_SHA_1, NULL, 0 };
    CK_MECHANISM_PTR mechanism;
    Tcl_Obj *obj_id, *obj_pubkeyinfo, *obj_pubkey, *obj_issuer, *obj_subject, *obj_serial_number;

    CK_ULONG resultbuf_len;

	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	int i;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL;
	unsigned long certder_len;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_cert;
	long slotid_long;
	int tcl_keylist_llength, idx;
	CK_SLOT_ID slotid;
	CK_RV chk_rv;
	Tcl_HashEntry *tcl_handle_entry;
	int tcl_rv;
	struct x509_object x509;
	ssize_t x509_read_ret;

//fprintf(stderr, "tclpkcs11_perform_pki_pubkeyinfo objc=%d\n",  objc);
	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::pubkeyinfo cert_der_hex list_token\"", -1));
		return(TCL_ERROR);
	}

	tcl_cert = objv[1]; /*hash from doc*/
//fprintf(stderr,"CERT_DER=%s\n", Tcl_GetString(tcl_cert));
	cert_der = ckalloc(Tcl_GetCharLength(tcl_cert) / 2);
//fprintf(stderr, "tclpkcs11_perform_pki_pubkeyinfo certder_len=%i\n", Tcl_GetCharLength(tcl_cert) / 2);
	certder_len = tclpkcs11_string_to_bytearray(tcl_cert, cert_der, Tcl_GetCharLength(tcl_cert) / 2);
//fprintf(stderr, "tclpkcs11_perform_pki_pubkeyinfo certder_len=%lu\n", certder_len);
	x509_read_ret = asn1_x509_read_object(cert_der, certder_len, &x509);
	if (x509_read_ret == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("bad certificate", -1));
		return(TCL_ERROR);
	}
	tcl_keylist = objv[2];/*CKA for cert + handle + ckaid*/
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));
		return(TCL_ERROR);
	}
	i = 0;
	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];
//fprintf(stderr,"Pubkeyinfo h_slotid=%s\n", Tcl_GetString(tcl_keylist_key));

		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;
			i++;
			continue;
		}
	}
//fprintf(stderr,"tclpkcs11_perform_pki_pubketyinfo: List END i=%i\n", i);
	if (i != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid  handle or slot or param", -1));
		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle 1", -1));

		return(TCL_ERROR);
	}

	slotid_long = atol(Tcl_GetString(tcl_slotid));
	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}
//Calculate CKA_ID
	mechanism = &mechanism_desc_sha1;
	chk_rv = handle->pkcs11->C_DigestInit(handle->session, mechanism);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}
	resultbuf_len = 20;
	chk_rv = handle->pkcs11->C_Digest(handle->session, (CK_BYTE *)(x509.pubkey.contents) + 1, x509.pubkey.size - 1, (CK_BYTE*)&cka_id, &resultbuf_len);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}
//Calculate CKA_ID EMD
	/* Create the current item list */
	curr_item_list = Tcl_NewObj();
	/* Convert the ID into a readable string */
	obj_id = tclpkcs11_bytearray_to_string((const unsigned char *)&cka_id, 20);
	Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_id", -1));
	Tcl_ListObjAppendElement(interp, curr_item_list, obj_id);

	/* Convert the PUBKEYINFO into a readable string */
	pks = (unsigned char *)x509.pubkeyinfo.asn1rep;
//fprintf(stderr,"tclpkcs11_perform_pki_pubketyinfo: List PKS=0x%2x,0x%2x,0x%2x,0x%2x,\n", pks[0], pks[1], pks[2], pks[3]);
	if ((unsigned char)pks[1] > (unsigned char)0x80) {
	    seek = 3;
	} else {
	    seek = 2;
	}
	obj_pubkeyinfo = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.pubkeyinfo.asn1rep) + seek, x509.pubkeyinfo.asn1rep_len - seek);
	Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pubkeyinfo", -1));
	Tcl_ListObjAppendElement(interp, curr_item_list, obj_pubkeyinfo);

	/* Convert the PUBKEY into a readable string */
	obj_pubkey = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.pubkey.contents) + 1, x509.pubkey.size - 1);
	Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pubkey", -1));
	Tcl_ListObjAppendElement(interp, curr_item_list, obj_pubkey);
	/* Convert the SUBJECT into a readable string */
	obj_subject = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.subject.asn1rep), x509.subject.asn1rep_len);
	Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("subject", -1));
	Tcl_ListObjAppendElement(interp, curr_item_list, obj_subject);
	/* Convert the ISSUER into a readable string */
	obj_issuer = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.issuer.asn1rep), x509.issuer.asn1rep_len);
	Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("issuer", -1));
	Tcl_ListObjAppendElement(interp, curr_item_list, obj_issuer);
	/* Convert the SERIAL_NUNBER into a readable string */
	obj_serial_number = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.serial_number.asn1rep), x509.serial_number.asn1rep_len);
	Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("serial_number", -1));
	Tcl_ListObjAppendElement(interp, curr_item_list, obj_serial_number);

	Tcl_SetObjResult(interp, curr_item_list);
	return(TCL_OK);
}




MODULE_SCOPE int tclpkcs11_perform_pki_importcert(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    static CK_BBOOL        ltrue       = CK_TRUE;
    static CK_BBOOL        lfalse      = CK_FALSE;
/*
    static CK_BYTE         gost28147params[] = {
	0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01
    };
*/
    CK_BYTE *cert_der;
    CK_OBJECT_HANDLE pub_key = CK_INVALID_HANDLE;

    static CK_OBJECT_CLASS     oclass_cert     = CKO_CERTIFICATE;
    static CK_CERTIFICATE_TYPE ocert_type      = CKC_X_509;
    static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
    static CK_OBJECT_CLASS oclass_priv = CKO_PRIVATE_KEY;
    long serial_num = 0;
    CK_MECHANISM     mechanism_desc_sha1 = { CKM_SHA_1, NULL, 0 };
    CK_MECHANISM_PTR mechanism;
    Tcl_Obj *tcl_result;

    CK_ATTRIBUTE           templ_certimport[] = {
        { CKA_CLASS,                &oclass_cert,     sizeof(oclass_cert)},
        { CKA_CERTIFICATE_TYPE,     &ocert_type,      sizeof(ocert_type)},
        { CKA_ID,		    NULL,			0  },
        { CKA_TOKEN,                &ltrue,           sizeof(ltrue)},
        { CKA_PRIVATE,              &lfalse,          sizeof(lfalse)},
        { CKA_LABEL,                NULL,			0 },	// 5
        { CKA_SUBJECT,              NULL,			0 },	// 6
        { CKA_ISSUER,               NULL,			0 },	// 6
        { CKA_VALUE,                NULL, 			0 },
        { CKA_SERIAL_NUMBER,        &serial_num,      sizeof(serial_num)},
    };
    CK_ATTRIBUTE template[] = {
	        {CKA_ID, NULL, 0},
	        {CKA_CLASS, NULL, 0},
    };

    CK_ATTRIBUTE      attr_update[] = {
        { CKA_LABEL, NULL, 0     },
    };
    CK_ULONG resultbuf_len;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG foundObjs;

	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	int i;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL;
	Tcl_Obj *tcl_label = NULL; 
	unsigned long certder_len;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_cert;
	long slotid_long;
	int tcl_keylist_llength, idx;
	CK_SLOT_ID slotid;
	CK_RV chk_rv;
	Tcl_HashEntry *tcl_handle_entry;
	int tcl_rv;
	struct x509_object x509;
	ssize_t x509_read_ret;

//fprintf(stderr, "tclpkcs11_perform_pki_importcert objc=%d\n",  objc);
	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::importcert cert_der_hex list_token_and_cka\"", -1));
		return(TCL_ERROR);
	}

	tcl_cert = objv[1]; /*hash from doc*/
//fprintf(stderr,"CERT_DER=%s\n", Tcl_GetString(tcl_cert));
	cert_der = ckalloc(Tcl_GetCharLength(tcl_cert) / 2);
//fprintf(stderr, "tclpkcs11_perform_pki_importcert certder_len=%i\n", Tcl_GetCharLength(tcl_cert) / 2);
	certder_len = tclpkcs11_string_to_bytearray(tcl_cert, cert_der, Tcl_GetCharLength(tcl_cert) / 2);
//fprintf(stderr, "tclpkcs11_perform_pki_importcert certder_len=%lu\n", certder_len);
	x509_read_ret = asn1_x509_read_object(cert_der, certder_len, &x509);
	if (x509_read_ret == -1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("bad certificate", -1));
		return(TCL_ERROR);
	}
//Заполняем templ
	templ_certimport[8].pValue = cert_der;
	templ_certimport[8].ulValueLen = certder_len;
	templ_certimport[6].pValue = x509.subject.asn1rep;
	templ_certimport[6].ulValueLen = x509.subject.asn1rep_len;
	templ_certimport[7].pValue = x509.issuer.asn1rep;
	templ_certimport[7].ulValueLen = x509.issuer.asn1rep_len;
	templ_certimport[9].pValue = x509.serial_number.asn1rep;
	templ_certimport[9].ulValueLen = x509.serial_number.asn1rep_len;
//fprintf(stderr, "tclpkcs11_perform_pki_importcert TEMPL END\n");
//Заполняем templ конец
	tcl_keylist = objv[2];/*CKA for cert + handle + ckaid*/
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));
		return(TCL_ERROR);
	}
	i = 0;
	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];
//fprintf(stderr,"Import h_slotid=%s\n", Tcl_GetString(tcl_keylist_key));

		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_label") == 0) {
			tcl_label = tcl_keylist_val;
//fprintf(stderr,"CKA_LABEL=%s\n", Tcl_GetString(tcl_label));
			templ_certimport[5].pValue = Tcl_GetString(tcl_label);
			templ_certimport[5].ulValueLen = (unsigned long)strlen(Tcl_GetString(tcl_label));
			attr_update[0].pValue = Tcl_GetString(tcl_label);
			attr_update[0].ulValueLen = templ_certimport[5].ulValueLen;
			i++;
			continue;
		}
	}
//fprintf(stderr,"tclpkcs11_perform_pki_importcert: List END i=%i\n", i);
	if (i != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid  handle or slot or param", -1));
		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	slotid_long = atol(Tcl_GetString(tcl_slotid));
	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}
//Calculare CKA_ID
	template[0].pValue = ckalloc(20);
	template[0].ulValueLen = 20;
	mechanism = &mechanism_desc_sha1;
	chk_rv = handle->pkcs11->C_DigestInit(handle->session, mechanism);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}
	resultbuf_len = 20;
	chk_rv = handle->pkcs11->C_Digest(handle->session, (CK_BYTE *)(x509.pubkey.contents) + 1, x509.pubkey.size - 1, template[0].pValue, &resultbuf_len);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		return(TCL_ERROR);
	}
	templ_certimport[2].pValue = template[0].pValue;
	templ_certimport[2].ulValueLen = template[0].ulValueLen;
	
//Calculare CKA_ID EMD
/*Check exist certificate with the CKA_ID*/
	template[1].pValue = &oclass_cert;     
	template[1].ulValueLen = sizeof(oclass_cert);
	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(CK_ATTRIBUTE));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	}
	/* Terminate Search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);
//fprintf(stderr, "tclpkcs11_perform_pki_importcert:cert final Find=%lu\n", foundObjs);

	if (foundObjs > 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Certificate with the CKA_ID exist", -1));
		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_CreateObject(handle->session, templ_certimport, sizeof(templ_certimport) / sizeof(CK_ATTRIBUTE), &pub_key);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("importcert: cannot create publickey", -1));
		return(TCL_ERROR);
	}
//    fprintf(stderr, "C_CreateObject certificate OK\n");
/*Find publickey with the CKA_ID*/
	template[1].pValue = &oclass_pub;
	template[1].ulValueLen = sizeof(oclass_pub);

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	}
	/* Terminate Search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	if (foundObjs == 1) {
	    chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
//fprintf(stderr, "Import set label to public_key\n");
	}
/*Find privatekey with the CKA_ID*/
	template[1].pValue = &oclass_priv;
	template[1].ulValueLen = sizeof(oclass_priv);
	
	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	}
	/* Terminate Search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	if (foundObjs == 1) {
	    chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
//fprintf(stderr, "Import set label to private_key\n");
	}


//finish:

	tcl_result = tclpkcs11_bytearray_to_string(templ_certimport[2].pValue, templ_certimport[2].ulValueLen);

	ckfree(templ_certimport[2].pValue);
//	ckfree(templ_certimport[6].pValue);
//	ckfree(templ_certimport[8].pValue);
//fprintf(stderr,"tclpkcs11_perform_pki_importcert OK\n");
	Tcl_SetObjResult(interp, tcl_result);
	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_perform_pki_verify(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    static CK_BBOOL        ltrue       = CK_TRUE;
    static CK_BBOOL        lfalse       = CK_FALSE;
    static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
    CK_KEY_TYPE     key_type    = CKK_GOSTR3410; //CKK_GOSTR3410_512
    static CK_UTF8CHAR     *label         = (CK_UTF8CHAR *)"Yet Another Keypair";
    static CK_BYTE         gost28147params[] = {
	0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01
    };
    CK_BYTE *digest;
    CK_BYTE *signature;
    CK_BYTE *pubkeyinfo;
    CK_OBJECT_HANDLE pub_key = CK_INVALID_HANDLE;
    CK_MECHANISM           mechanism_desc     = { CKM_GOSTR3410, NULL, 0 };
    CK_MECHANISM           mechanism_desc_512     = { CKM_GOSTR3410_512, NULL, 0 };
    CK_MECHANISM_PTR       mechanism          = &mechanism_desc;

	CK_ULONG label_len = (unsigned long)strlen((char *)label) + 1;
	CK_ATTRIBUTE           pub_template[] = {
	    { CKA_CLASS,		&oclass_pub,		sizeof(oclass_pub)},
	    { CKA_KEY_TYPE,		&key_type,		sizeof(key_type)},
    	    { CKA_TOKEN,		&lfalse,		sizeof(lfalse)},
    	    { CKA_GOSTR3410PARAMS,	NULL, 			0},
    	    { CKA_GOSTR3411PARAMS,	NULL, 			0},
	    { CKA_GOST28147_PARAMS, 	gost28147params,	sizeof(gost28147params)	},
    	    { CKA_VERIFY,		&ltrue,			sizeof(CK_BBOOL)},
    	    { CKA_ENCRYPT,		&ltrue,			sizeof(CK_BBOOL)},
	    { CKA_LABEL,		NULL,			0 },
    	    { CKA_VALUE,		NULL,			0 },
	};
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	int i;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL;
	Tcl_Obj *tcl_pubkeyinfo = NULL;
	unsigned long digest_len;
	unsigned long signature_len;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_hash, *tcl_signature;
	long slotid_long;
	int tcl_keylist_llength, idx;
	CK_SLOT_ID slotid;
	CK_RV chk_rv;
	Tcl_HashEntry *tcl_handle_entry;
	int tcl_rv;
//fprintf(stderr, "tclpkcs11_perform_pki_verify objc=%d\n",  objc);

	tcl_hash = objv[1]; /*hash from doc*/
//fprintf(stderr,"HASH=%s\n", Tcl_GetString(tcl_hash));
	digest = ckalloc(Tcl_GetCharLength(tcl_hash) / 2);
//fprintf(stderr, "tclpkcs11_perform_pki_verify digest_len=%i\n", Tcl_GetCharLength(tcl_hash) / 2);
	digest_len = tclpkcs11_string_to_bytearray(tcl_hash, digest, Tcl_GetCharLength(tcl_hash) / 2);
//fprintf(stderr, "tclpkcs11_perform_pki_verify digest_len=%lu\n", digest_len);
	if (digest_len != 32 && digest_len != 64) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("bad length hash", -1));
		return(TCL_ERROR);
	}
	tcl_signature = objv[2];/*signature doc*/
	signature = ckalloc(Tcl_GetCharLength(tcl_signature) / 2);
	signature_len = tclpkcs11_string_to_bytearray(tcl_signature, signature, Tcl_GetCharLength(tcl_signature) / 2);
	if (signature_len != 64 && signature_len != 128) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("bad length signatute", -1));
		return(TCL_ERROR);
	}
//fprintf(stderr, "tclpkcs11_perform_pki_verify signature_len=%lu\n", signature_len);
	tcl_keylist = objv[3];/*pubkey CA*/
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));
		return(TCL_ERROR);
	}
	i = 0;
	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];
//fprintf(stderr,"Verify h_slotid=%s\n", Tcl_GetString(tcl_keylist_key));

		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;
//fprintf(stderr,"Verify H=%s\n", Tcl_GetString(tcl_handle));
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;
//fprintf(stderr,"Verify Slot=%s\n", Tcl_GetString(tcl_slotid));
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pubkeyinfo") == 0) {
			CK_BYTE oidgost[] = {0x2a, 0x85, 0x03};
			CK_BYTE hexoidpk512[] = {0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x1, 0x02};
			int l, l1, seek;
			CK_BYTE *pki, *pkv;
			tcl_pubkeyinfo = tcl_keylist_val;
//fprintf(stderr,"PUBKEYINFO=%s\nPUBKEYINFO_LEN_alloc=%i\n", Tcl_GetString(tcl_pubkeyinfo), Tcl_GetCharLength(tcl_pubkeyinfo) / 2);
			pubkeyinfo = ckalloc(Tcl_GetCharLength(tcl_pubkeyinfo) / 2);
			tclpkcs11_string_to_bytearray(tcl_pubkeyinfo, pubkeyinfo, Tcl_GetCharLength(tcl_pubkeyinfo) / 2);
//fprintf(stderr,"PUBKEYINFO_LEN=%lu\n", tcl_strtobytearray_rv);
			pki = pubkeyinfo;
			if (pki[0] != 0x30){
			    Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid pubkeyinfo", -1));
			    return(TCL_ERROR);
			}
			l = (int)pki[1];
			pki += 2;
			if (pki[l] != 0x03) {
			    Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid pubkeyinfo 1", -1));
			    return(TCL_ERROR);
			}
//fprintf(stderr,"PUBKEYINFO 1111 LENPAR l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[l + 0], pki[l + 1], pki[l + 2]);
			if (pki[l + 1] > 0x80) {
			    seek = 6;
			    l1 = 128;
			} else {
			    seek = 4;
			    l1 = 64;
			}
//Начало ключа
			pkv = pki + 1 + seek + l;
			pub_template[9].pValue = ckalloc(l1);
//fprintf(stderr,"PUBKEYINFO 1111PVK LENPAR l1=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l1, pkv[0], pkv[1], pkv[2]);
			memmove (pub_template[9].pValue, pkv, l1);
			pub_template[9].ulValueLen = l1;
//Параметры
			if (pki[0] != 0x06) {
			    Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid pubkeyinfo 2", -1));
			    return(TCL_ERROR);
			}
//Тип ключа
			l = (int)pki[1];
			pki += 2;
//fprintf(stderr,"PUBKEYINFO LENPAR TPK l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[0], pki[1], pki[2]);
			if (memcmp(pki, oidgost, sizeof(oidgost))) {
			    Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid pubkeyinfo bad type key (not gost)", -1));
			    return(TCL_ERROR);
			}
			if (!memcmp(pki, hexoidpk512, sizeof(hexoidpk512))) {
				key_type = CKK_GOSTR3410_512;
				mechanism = &mechanism_desc_512;
				if (digest_len != 64) {
				    Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::verify CKK_GOSTR3410_512 digest\" - bad len hash", -1));
				    return(TCL_ERROR);
				}
			} else {
				key_type = CKK_GOSTR3410;
				mechanism = &mechanism_desc;
				if (digest_len != 32) {
				    Tcl_SetObjResult(interp, Tcl_NewStringObj("\"pki::pkcs11::verify CKK_GOSTR3410 digest\" - bad len hash", -1));
				    return(TCL_ERROR);
				}
			}

			pki = pki + l + 2;
//gostr3410param
//fprintf(stderr,"PUBKEYINFO SIGN LENPAR l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[0], pki[1], pki[2]);
			l = (int)pki[1];
			pub_template[3].pValue = ckalloc(l + 2);
			memcpy(pub_template[3].pValue, pki, l + 2);
			pub_template[3].ulValueLen = l + 2;
//gostr3411param

			pki = pki + l + 2;
			l = (int)pki[1];
//fprintf(stderr,"PUBKEYINFO HASH LENPAR l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[0], pki[1], pki[2]);
			pub_template[4].pValue = ckalloc(l + 2);
			memcpy(pub_template[4].pValue, pki, l + 2);
			pub_template[4].ulValueLen = l + 2;

			i++;
			continue;
		}
	}
//fprintf(stderr,"tclpkcs11_perform_pki_verify: List END\n");
	if (i != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid pubkey or handle or slot or param", -1));
		return(TCL_ERROR);
	}
	pub_template[8].pValue = label;
	pub_template[8].ulValueLen = label_len;

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	slotid_long = atol(Tcl_GetString(tcl_slotid));
	slotid = slotid_long;

//fprintf(stderr,"tclpkcs11_perform_pki_verifyt Verify slotid=%lu\n", slotid);
	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}


//fprintf(stderr,"tclpkcs11_perform_pki_verify SESSION OK\n");
	chk_rv = handle->pkcs11->C_CreateObject(handle->session, pub_template, sizeof(pub_template) / sizeof(CK_ATTRIBUTE), &pub_key);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("verify: cannot create publickey", -1));
		return(TCL_ERROR);
	}
//fprintf(stderr, "C_CreateObject public key OK\n");
	chk_rv = handle->pkcs11->C_VerifyInit(handle->session, mechanism, pub_key);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("C_VerifyInit bad", -1));
		return(TCL_ERROR);
	}
	chk_rv = handle->pkcs11->C_Verify(handle->session, digest, digest_len, signature, signature_len);

//finish:
	handle->pkcs11->C_DestroyObject(handle->session, pub_key);
	ckfree(digest);
	ckfree(signature);
	ckfree(pub_template[3].pValue);
	ckfree(pub_template[4].pValue);
	ckfree(pub_template[9].pValue);
	
	
	if (chk_rv != CKR_OK) {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj("0", -1));
	    return(TCL_OK);
	} else {
//fprintf(stderr,"tclpkcs11_perform_pki_verify OK\n");
	    Tcl_SetObjResult(interp, Tcl_NewStringObj("1", -1));
	    return(TCL_OK);
	}
}

MODULE_SCOPE int tclpkcs11_perform_pki_delete(int del, ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
/*del = 1 - delete, 0 -  rename*/
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	char *mode;
	unsigned long tcl_strtobytearray_rv;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_mode, *tcl_ckaid, *tcl_label;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL;
	long slotid_long;
	int tcl_keylist_llength, idx;
	int tcl_rv;
	static CK_OBJECT_CLASS     oclass_cert     = CKO_CERTIFICATE;
	static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
	static CK_OBJECT_CLASS oclass_priv = CKO_PRIVATE_KEY;
//	static CK_OBJECT_CLASS oclass_data = CKO_DATA;
	int i;
	CK_SLOT_ID slotid;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG foundObjs;
	CK_ATTRIBUTE      attr_update[] = {
    	    { CKA_LABEL, NULL, 0     },
	};
	CK_ATTRIBUTE template[] = {
	                           {CKA_ID, NULL, 0},
	                           {CKA_CLASS, NULL, 0},
	};
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::delete cert|key|all keylist\"", -1));
		return(TCL_ERROR);
	}

	tcl_mode = objv[1];
	tcl_keylist = objv[2];
	mode = Tcl_GetString(tcl_mode);
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));
		return(TCL_ERROR);
	}
	i = 0;
	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];
//fprintf(stderr,"Delete h_slotid=%s\n", Tcl_GetString(tcl_keylist_key));

		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;
//fprintf(stderr,"Delete H=%s\n", Tcl_GetString(tcl_handle));
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;
//fprintf(stderr,"Delete Slot=%s\n", Tcl_GetString(tcl_slotid));
			i++;
			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_id") == 0) {
			tcl_ckaid = tcl_keylist_val;
//fprintf(stderr,"Delete CKA_ID=\"%s\" \nLenID=%i\n", Tcl_GetString(tcl_ckaid), Tcl_GetCharLength(tcl_ckaid) / 2);
			template[0].pValue = ckalloc(Tcl_GetCharLength(tcl_ckaid) / 2);
			tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_ckaid, template[0].pValue, Tcl_GetCharLength(tcl_ckaid) / 2);
			template[0].ulValueLen = tcl_strtobytearray_rv;
//fprintf(stderr,"Delete LenID=%lu, temp=%lu\n", tcl_strtobytearray_rv, template[0].ulValueLen);
			i++;
			continue;
		}
		if (del == 0 ) {
		    if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_label") == 0) {
			tcl_label = tcl_keylist_val;
//fprintf(stderr,"CKA_LABEL=%s\n", Tcl_GetString(tcl_label));
			attr_update[0].pValue = Tcl_GetString(tcl_label);
			attr_update[0].ulValueLen = (unsigned long)strlen(Tcl_GetString(tcl_label));
			i++;
			continue;
		    }
		}
		
	}
//fprintf(stderr,"tclpkcs11_perform_pki_delete: List END i=%i\n", i);
	if ((del == 1) && (i != 3)) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid  handle or slot or pkcs11_id", -1));
		return(TCL_ERROR);
	}
	if ((del == 0) && (i != 4)) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid  handle or slot or pkcs11_id or pkcs11_label", -1));
		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	slotid_long = atol(Tcl_GetString(tcl_slotid));
	slotid = slotid_long;

//fprintf(stderr,"tclpkcs11_perform_pki_delete Import slotid=%lu\n", slotid);
	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}


	if (!strcmp((const char *)mode, "cert") || !strcmp((const char *)mode, "all")) {
//fprintf(stderr,"tclpkcs11_perform_pki_delete CERT mode=%s\n", mode);
	    template[1].pValue = &oclass_cert;
	    template[1].ulValueLen = sizeof(oclass_cert);
	    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	    }

	    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	    }
	/* Terminate Search */
	    handle->pkcs11->C_FindObjectsFinal(handle->session);

	    if (foundObjs == 1) {
		switch (del) {
		    case 0:
			chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
//fprintf(stderr, "Rename cert\n");
			break;
		    case 1:
			chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
//fprintf(stderr, "Delete cert");
			break;
		    default:
			break;
		}
		if (chk_rv != CKR_OK) {
		    Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		    return(TCL_ERROR);
		}
	    }

	}
	if (!strcmp((const char *)mode, "key") || !strcmp((const char *)mode, "all")) {
//	CKO_PUBLIC_KEY
	    template[1].pValue = &oclass_pub;
	    template[1].ulValueLen = sizeof(oclass_pub);

	    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	    }

	    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	    }
	/* Terminate Search */
	    handle->pkcs11->C_FindObjectsFinal(handle->session);

	    if (foundObjs == 1) {
		switch (del) {
		    case 0:
			chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
//fprintf(stderr, "Rename public_key\n");
			break;
		    case 1:
			chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
//fprintf(stderr, "Delete public_key\n");
			break;
		    default:
			break;
		}
		if (chk_rv != CKR_OK) {
		    Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		    return(TCL_ERROR);
		}
	    }

//	CKO_PRIVATE_KEY
//fprintf(stderr,"tclpkcs11_perform_pki_delete KEY mode=%s\n", mode);
	    template[1].pValue = &oclass_priv;
	    template[1].ulValueLen = sizeof(oclass_priv);

	    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	    }

	    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	    }
	/* Terminate Search */
	    handle->pkcs11->C_FindObjectsFinal(handle->session);

	    if (foundObjs == 1) {
		switch (del) {
		    case 0:
//fprintf(stderr, "Rename private_key\n");
			chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
			break;
		    case 1:
			chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
//fprintf(stderr, "Delete private_key\n");
			break;
		    default:
			break;
		}
		if (chk_rv != CKR_OK) {
		    Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		    return(TCL_ERROR);
		}
	    }

	}
/* CKO_DATA поиск объекта по метке. Позже добавим
	if (!strcmp((const char *)mode, "data")) {
	    template[1].pValue = &oclass_data;
	    template[1].ulValueLen = sizeof(oclass_data);

	    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	    }

	    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	    if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	    }
	// Terminate Search 
	    handle->pkcs11->C_FindObjectsFinal(handle->session);

	    if (foundObjs == 1) {
		switch (del) {
		    case 0:
			chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
//fprintf(stderr, "Rename public_key\n");
			break;
		    case 1:
			chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
//fprintf(stderr, "Delete public_key\n");
			break;
		    default:
			break;
		}
		if (chk_rv != CKR_OK) {
		    Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
		    return(TCL_ERROR);
		}
	    }
	}
*/

//fprintf(stderr,"tclpkcs11_perform_pki_delete mode=%s, type=%i\n", mode, del);
    return(TCL_OK);
}


MODULE_SCOPE int tclpkcs11_perform_pki(int encrypt, ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	unsigned char *input, resultbuf[1024];
	unsigned long tcl_strtobytearray_rv;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *pki_real_cmd;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_mode, *tcl_input;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL, *tcl_objid = NULL;
	Tcl_Obj *tcl_result;
	long slotid_long;
	int tcl_keylist_llength, idx;
	int input_len;
	CK_ULONG resultbuf_len;
	int sign, terminate;
	int tcl_rv;

	CK_SLOT_ID slotid;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG foundObjs;
	CK_OBJECT_CLASS objectclass_pk;
	CK_ATTRIBUTE template[] = {
	                           {CKA_ID, NULL, 0},
	                           {CKA_CLASS, NULL, 0},
	};
	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 4) {
		if (encrypt) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::encrypt mode input keylist\"", -1));
		} else {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::decrypt mode input keylist\"", -1));
		}

		return(TCL_ERROR);
	}

	tcl_mode = objv[1];
	tcl_input = objv[2];
	tcl_keylist = objv[3];

	/*
	 * Parse the "keylist" argument and remove the extraneous "type
	 * pkcs11" entry so we can pass it to around as needed
	 *
	 * Also, while we are here, pick out the elements we can
	 */
	/* Duplicate the object so we can modify it */
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));

		return(TCL_ERROR);
	}

	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];

		if (strcmp(Tcl_GetString(tcl_keylist_key), "type") == 0) {
			if (strcmp(Tcl_GetString(tcl_keylist_val), "pkcs11") == 0) {
				/* Remove "type pkcs11" from list */
				tcl_rv = Tcl_ListObjReplace(interp, tcl_keylist, idx, 2, 0, NULL);
			}

			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;

			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;

			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_id") == 0) {
			tcl_objid = tcl_keylist_val;

			continue;
		}
	}

	if (strcmp(Tcl_GetString(tcl_mode), "pub") == 0) {
		/* Public Key Operations can be performed by the Tcl PKI Module */
		pki_real_cmd = Tcl_NewObj();

		if (encrypt) {
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("::pki::encrypt", -1));
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-nopad", -1));
		} else {
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("::pki::decrypt", -1));
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-nounpad", -1));
		}

		Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-pub", -1));
		Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-binary", -1));
		Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("--", -1));
		Tcl_ListObjAppendElement(interp, pki_real_cmd, tcl_input);
		Tcl_ListObjAppendElement(interp, pki_real_cmd, tcl_keylist);

		return(Tcl_EvalObjEx(interp, pki_real_cmd, 0));
	}

	if (!tcl_handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_handle\" in keylist", -1));

		return(TCL_ERROR);
	}

	if (!tcl_slotid) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_slotid\" in keylist", -1));

		return(TCL_ERROR);
	}

	if (!tcl_objid) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_id\" in keylist", -1));

		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	/*
	 * Find the PKCS#11 object ID that cooresponds to this certificate's
	 * private key
	 */
	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* CKA_ID */
	template[0].pValue = ckalloc(Tcl_GetCharLength(tcl_objid) / 2);
	tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_objid, template[0].pValue, Tcl_GetCharLength(tcl_objid) / 2);
	template[0].ulValueLen = tcl_strtobytearray_rv;

	/* CKA_CLASS */
	objectclass_pk = CKO_PRIVATE_KEY;
	template[1].pValue = &objectclass_pk;
	template[1].ulValueLen = sizeof(objectclass_pk);

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	}

	/* Terminate Search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	if (foundObjs < 1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("PKCS11_ERROR MAYBE_LOGIN", -1));

		return(TCL_ERROR);
	}

	/* Perform the PKI operation (encrypt/decrypt) */
	input = Tcl_GetByteArrayFromObj(tcl_input, &input_len);
	if (encrypt) {
		sign = 0;
		chk_rv = handle->pkcs11->C_EncryptInit(handle->session, &mechanism, hObject);
		if (chk_rv != CKR_OK) {
			if (chk_rv == CKR_FUNCTION_NOT_SUPPORTED) {
				sign = 1;
				chk_rv = handle->pkcs11->C_SignInit(handle->session, &mechanism, hObject);
				if (chk_rv != CKR_OK) {
					Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

					return(TCL_ERROR);
				}
			}
		}

		resultbuf_len = sizeof(resultbuf);
		if (!sign) {
			chk_rv = handle->pkcs11->C_Encrypt(handle->session, input, input_len, resultbuf, &resultbuf_len);
		} else {
			/* Some PKCS#11 drivers will not accept pre-padded input, so we must unpad it here */
			if (input_len > 3) {
				if (input[0] == 0x00 && input[1] == 0x01) {
					input = input + 2;
					input_len -= 2;
					while (*input == 0xff && input_len > 0) {
						input++;
						input_len--;
					}

					if (input_len) {
						if (input[0] == 0x00) {
							input++;
							input_len--;
						}
					}
				}
			}

			chk_rv = handle->pkcs11->C_Sign(handle->session, input, input_len, resultbuf, &resultbuf_len);
		}

		terminate = 0;
		if (chk_rv == CKR_OK) {
			terminate = 1;
		} else {
			if (chk_rv == CKR_BUFFER_TOO_SMALL) {
				terminate = 1;
			}
		}

		if (terminate) {
			if (!sign) {
				handle->pkcs11->C_EncryptFinal(handle->session, NULL, 0);
			} else {
				handle->pkcs11->C_SignFinal(handle->session, NULL, 0);
			}
		}

		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}
	} else {
		chk_rv = handle->pkcs11->C_DecryptInit(handle->session, &mechanism, hObject);
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}

		resultbuf_len = sizeof(resultbuf);
		chk_rv = handle->pkcs11->C_Decrypt(handle->session, input, input_len, resultbuf, &resultbuf_len);
		if (chk_rv != CKR_OK) {
			if (chk_rv == CKR_BUFFER_TOO_SMALL) {
				/* Terminate decryption operation */
				handle->pkcs11->C_DecryptFinal(handle->session, NULL, 0);
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}
	}

	tcl_result = Tcl_NewByteArrayObj(resultbuf, resultbuf_len);

	Tcl_SetObjResult(interp, tcl_result);

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_encrypt(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	return(tclpkcs11_perform_pki(1, cd, interp, objc, objv));
}

MODULE_SCOPE int tclpkcs11_decrypt(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	return(tclpkcs11_perform_pki(0, cd, interp, objc, objv));
}
/*LISSI*/
MODULE_SCOPE int tclpkcs11_dgst(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "Digest1\n");
	return(tclpkcs11_perform_pki_dgst(cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_digest(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "Digest1\n");
	return(tclpkcs11_perform_pki_digest(cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_keypair(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "KEYPAIR\n");
	return(tclpkcs11_perform_pki_keypair(cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_delete(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "DELETE\n");
	return(tclpkcs11_perform_pki_delete(1, cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_rename(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "DELETE\n");
	return(tclpkcs11_perform_pki_delete(0, cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_sign(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "SIGN START\n");
	return(tclpkcs11_perform_pki_sign(cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_pkinfo(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "PKIINFO START\n");
	return(tclpkcs11_perform_pki_pkinfo(cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_verify(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "Verify START\n");
	return(tclpkcs11_perform_pki_verify(cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_importcert(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "Verify START\n");
	return(tclpkcs11_perform_pki_importcert(cd, interp, objc, objv));
}
MODULE_SCOPE int tclpkcs11_pubkeyinfo(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
//fprintf(stderr, "Verify START\n");
	return(tclpkcs11_perform_pki_pubkeyinfo(cd, interp, objc, objv));
}


MODULE_SCOPE void tclpkcs11_unloadall(ClientData cd) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_HashSearch search;

	if (!cd) {
		return;
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	for (
		tcl_handle_entry = Tcl_FirstHashEntry(&interpdata->handles, &search);
		tcl_handle_entry;
		tcl_handle_entry = Tcl_NextHashEntry(&search)
	) {

		handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);

		if (handle->pkcs11 && handle->pkcs11->C_Finalize) {
			handle->pkcs11->C_Finalize(NULL);
		}

		tclpkcs11_int_unload_module(handle->base);

		ckfree((char *) handle);

	}

	return;
}


/*
 * Tcl Loadable Module Initialization
 */
int Tclpkcs11_Init(Tcl_Interp *interp) {
	struct tclpkcs11_interpdata *interpdata;
	Tcl_Command tclCreatComm_ret;
	const char *tclPkgReq_ret;
	int tclPkgProv_ret;

#ifdef USE_TCL_STUBS
	const char *tclInitStubs_ret;

	/* Initialize Stubs */
	tclInitStubs_ret = Tcl_InitStubs(interp, "8.4", 0);
	if (!tclInitStubs_ret) {
		return(TCL_ERROR);
	}
#endif

	tclPkgReq_ret = Tcl_PkgRequire(interp, "pki", "0.1", 0);
	if (!tclPkgReq_ret) {
		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) ckalloc(sizeof(*interpdata));

	/* Initialize InterpData structure */
	Tcl_InitObjHashTable(&interpdata->handles);
	interpdata->handles_idx = 0;

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::loadmodule", tclpkcs11_load_module, interpdata, NULL);
	if (!tclCreatComm_ret) {
		ckfree((char *) interpdata);

		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::unloadmodule", tclpkcs11_unload_module, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::listslots", tclpkcs11_list_slots, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::listcerts", tclpkcs11_list_certs, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}


	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::login", tclpkcs11_login, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::logout", tclpkcs11_logout, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::encrypt", tclpkcs11_encrypt, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::decrypt", tclpkcs11_decrypt, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
/*LISSI*/
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::listmechs", tclpkcs11_listmechs, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::listcertsder", tclpkcs11_list_certs_der, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::listobjects", tclpkcs11_list_objects, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::dgst", tclpkcs11_dgst, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::digest", tclpkcs11_digest, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::keypair", tclpkcs11_keypair, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::delete", tclpkcs11_delete, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::rename", tclpkcs11_rename, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::sign", tclpkcs11_sign, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::pkinfo", tclpkcs11_pkinfo, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::verify", tclpkcs11_verify, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::importcert", tclpkcs11_importcert, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}
	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::pubkeyinfo", tclpkcs11_pubkeyinfo, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}


	/* Create an exit handler to unload and close all PKCS#11 modules */
	Tcl_CreateExitHandler(tclpkcs11_unloadall, interpdata);

	/* Register PKI handlers */
	Tcl_ObjSetVar2(interp,
	               Tcl_NewStringObj("pki::handlers", -1),
	               Tcl_NewStringObj("pkcs11", -1),
	               Tcl_NewStringObj("::pki::pkcs11::encrypt ::pki::pkcs11::decrypt", -1),
	               TCL_GLOBAL_ONLY
	              );

	tclPkgProv_ret = Tcl_PkgProvide(interp, "pki::pkcs11", PACKAGE_VERSION);
	if (tclPkgProv_ret != TCL_OK) {
		return(tclPkgProv_ret);
	}

	return(TCL_OK);
}
