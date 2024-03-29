
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */


#include <trousers/tss.h>

#define TSS_ERROR_LAYER(x)      (x & 0x3000)
#define TSS_ERROR_CODE(x)       (x & TSS_MAX_ERROR)


// from common.c (ltp-tss)
char *err_string(TSS_RESULT r)
{
	/* Check the return code to see if it is common to all layers.
	 * If so, return it.
	 */
	switch (TSS_ERROR_CODE(r)) {
		case TSS_SUCCESS:	return "TSS_SUCCESS";
		default:
			break;
	}

	/* The return code is either unknown, or specific to a layer */
	if (TSS_ERROR_LAYER(r) == TSS_LAYER_TPM) {
		switch (TSS_ERROR_CODE(r)) {
			case TCPA_E_AUTHFAIL:		return "TCPA_E_AUTHFAIL";
			case TCPA_E_BADINDEX:		return "TCPA_E_BADINDEX";
			case TCPA_E_AUDITFAILURE:	return "TCPA_E_AUDITFAILURE";
			case TCPA_E_CLEAR_DISABLED:	return "TCPA_E_CLEAR_DISABLED";
			case TCPA_E_DEACTIVATED:	return "TCPA_E_DEACTIVATED";
			case TCPA_E_DISABLED:		return "TCPA_E_DISABLED";
			case TCPA_E_DISABLED_CMD:	return "TCPA_E_DISABLED_CMD";
			case TCPA_E_FAIL:		return "TCPA_E_FAIL";
			case TCPA_E_INACTIVE:		return "TCPA_E_INACTIVE";
			case TCPA_E_INSTALL_DISABLED:	return "TCPA_E_INSTALL_DISABLED";
			case TCPA_E_INVALID_KEYHANDLE:	return "TCPA_E_INVALID_KEYHANDLE";
			case TCPA_E_KEYNOTFOUND:	return "TCPA_E_KEYNOTFOUND";
			case TCPA_E_NEED_SELFTEST:	return "TCPA_E_NEED_SELFTEST";
			case TCPA_E_MIGRATEFAIL:	return "TCPA_E_MIGRATEFAIL";
			case TCPA_E_NO_PCR_INFO:	return "TCPA_E_NO_PCR_INFO";
			case TCPA_E_NOSPACE:		return "TCPA_E_NOSPACE";
			case TCPA_E_NOSRK:		return "TCPA_E_NOSRK";
			case TCPA_E_NOTSEALED_BLOB:	return "TCPA_E_NOTSEALED_BLOB";
			case TCPA_E_OWNER_SET:		return "TCPA_E_OWNER_SET";
			case TCPA_E_RESOURCES:		return "TCPA_E_RESOURCES";
			case TCPA_E_SHORTRANDOM:	return "TCPA_E_SHORTRANDOM";
			case TCPA_E_SIZE:		return "TCPA_E_SIZE";
			case TCPA_E_WRONGPCRVAL:	return "TCPA_E_WRONGPCRVAL";
			case TCPA_E_BAD_PARAM_SIZE:	return "TCPA_E_BAD_PARAM_SIZE";
			case TCPA_E_SHA_THREAD:		return "TCPA_E_SHA_THREAD";
			case TCPA_E_SHA_ERROR:		return "TCPA_E_SHA_ERROR";
			case TCPA_E_FAILEDSELFTEST:	return "TCPA_E_FAILEDSELFTEST";
			case TCPA_E_AUTH2FAIL:		return "TCPA_E_AUTH2FAIL";
			case TCPA_E_BADTAG:		return "TCPA_E_BADTAG";
			case TCPA_E_IOERROR:		return "TCPA_E_IOERROR";
			case TCPA_E_ENCRYPT_ERROR:	return "TCPA_E_ENCRYPT_ERROR";
			case TCPA_E_DECRYPT_ERROR:	return "TCPA_E_DECRYPT_ERROR";
			case TCPA_E_INVALID_AUTHHANDLE:	return "TCPA_E_INVALID_AUTHHANDLE";
			case TCPA_E_NO_ENDORSEMENT:	return "TCPA_E_NO_ENDORSEMENT";
			case TCPA_E_INVALID_KEYUSAGE:	return "TCPA_E_INVALID_KEYUSAGE";
			case TCPA_E_WRONG_ENTITYTYPE:	return "TCPA_E_WRONG_ENTITYTYPE";
			case TCPA_E_INVALID_POSTINIT:	return "TCPA_E_INVALID_POSTINIT";
			case TCPA_E_INAPPROPRIATE_SIG:	return "TCPA_E_INAPPROPRIATE_SIG";
			case TCPA_E_BAD_KEY_PROPERTY:	return "TCPA_E_BAD_KEY_PROPERTY";
			case TCPA_E_BAD_MIGRATION:	return "TCPA_E_BAD_MIGRATION";
			case TCPA_E_BAD_SCHEME:		return "TCPA_E_BAD_SCHEME";
			case TCPA_E_BAD_DATASIZE:	return "TCPA_E_BAD_DATASIZE";
			case TCPA_E_BAD_MODE:		return "TCPA_E_BAD_MODE";
			case TCPA_E_BAD_PRESENCE:	return "TCPA_E_BAD_PRESENCE";
			case TCPA_E_BAD_VERSION:	return "TCPA_E_BAD_VERSION";
			case TCPA_E_RETRY:		return "TCPA_E_RETRY";
			default:			return "UNKNOWN TPM ERROR";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TDDL) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TDDL_E_COMPONENT_NOT_FOUND:	return "TDDL_E_COMPONENT_NOT_FOUND";
			case TDDL_E_ALREADY_OPENED:		return "TDDL_E_ALREADY_OPENED";
			case TDDL_E_BADTAG:			return "TDDL_E_BADTAG";
			case TDDL_E_INSUFFICIENT_BUFFER:	return "TDDL_E_INSUFFICIENT_BUFFER";
			case TDDL_E_COMMAND_COMPLETED:		return "TDDL_E_COMMAND_COMPLETED";
			case TDDL_E_ALREADY_CLOSED:		return "TDDL_E_ALREADY_CLOSED";
			case TDDL_E_IOERROR:			return "TDDL_E_IOERROR";
			default:				return "UNKNOWN TDDL ERROR";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TCS) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TCS_E_KEY_MISMATCH:		return "TCS_E_KEY_MISMATCH";
			case TCS_E_KM_LOADFAILED:		return "TCS_E_KM_LOADFAILED";
			case TCS_E_KEY_CONTEXT_RELOAD:		return "TCS_E_KEY_CONTEXT_RELOAD";
			case TCS_E_INVALID_CONTEXTHANDLE:	return "TCS_E_INVALID_CONTEXTHANDLE";
			case TCS_E_INVALID_KEYHANDLE:		return "TCS_E_INVALID_KEYHANDLE";
			case TCS_E_INVALID_AUTHHANDLE:		return "TCS_E_INVALID_AUTHHANDLE";
			case TCS_E_INVALID_AUTHSESSION:		return "TCS_E_INVALID_AUTHSESSION";
			case TCS_E_INVALID_KEY:			return "TCS_E_INVALID_KEY";
			default:				return "UNKNOWN TCS ERROR";
		}
	} else {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TSS_E_INVALID_OBJECT_TYPE:		return "TSS_E_INVALID_OBJECT_TYPE";
			case TSS_E_INVALID_OBJECT_INITFLAG:	return "TSS_E_INVALID_OBJECT_INITFLAG";
			case TSS_E_INVALID_HANDLE:		return "TSS_E_INVALID_HANDLE";
			case TSS_E_NO_CONNECTION:		return "TSS_E_NO_CONNECTION";
			case TSS_E_CONNECTION_FAILED:		return "TSS_E_CONNECTION_FAILED";
			case TSS_E_CONNECTION_BROKEN:		return "TSS_E_CONNECTION_BROKEN";
			case TSS_E_HASH_INVALID_ALG:		return "TSS_E_HASH_INVALID_ALG";
			case TSS_E_HASH_INVALID_LENGTH:		return "TSS_E_HASH_INVALID_LENGTH";
			case TSS_E_HASH_NO_DATA:		return "TSS_E_HASH_NO_DATA";
			case TSS_E_SILENT_CONTEXT:		return "TSS_E_SILENT_CONTEXT";
			case TSS_E_INVALID_ATTRIB_FLAG:		return "TSS_E_INVALID_ATTRIB_FLAG";
			case TSS_E_INVALID_ATTRIB_SUBFLAG:	return "TSS_E_INVALID_ATTRIB_SUBFLAG";
			case TSS_E_INVALID_ATTRIB_DATA:		return "TSS_E_INVALID_ATTRIB_DATA";
			case TSS_E_NO_PCRS_SET:			return "TSS_E_NO_PCRS_SET";
			case TSS_E_KEY_NOT_LOADED:		return "TSS_E_KEY_NOT_LOADED";
			case TSS_E_KEY_NOT_SET:			return "TSS_E_KEY_NOT_SET";
			case TSS_E_VALIDATION_FAILED:		return "TSS_E_VALIDATION_FAILED";
			case TSS_E_TSP_AUTHREQUIRED:		return "TSS_E_TSP_AUTHREQUIRED";
			case TSS_E_TSP_AUTH2REQUIRED:		return "TSS_E_TSP_AUTH2REQUIRED";
			case TSS_E_TSP_AUTHFAIL:		return "TSS_E_TSP_AUTHFAIL";
			case TSS_E_TSP_AUTH2FAIL:		return "TSS_E_TSP_AUTH2FAIL";
			case TSS_E_KEY_NO_MIGRATION_POLICY:	return "TSS_E_KEY_NO_MIGRATION_POLICY";
			case TSS_E_POLICY_NO_SECRET:		return "TSS_E_POLICY_NO_SECRET";
			case TSS_E_INVALID_OBJ_ACCESS:		return "TSS_E_INVALID_OBJ_ACCESS";
			case TSS_E_INVALID_ENCSCHEME:		return "TSS_E_INVALID_ENCSCHEME";
			case TSS_E_INVALID_SIGSCHEME:		return "TSS_E_INVALID_SIGSCHEME";
			case TSS_E_ENC_INVALID_LENGTH:		return "TSS_E_ENC_INVALID_LENGTH";
			case TSS_E_ENC_NO_DATA:			return "TSS_E_ENC_NO_DATA";
			case TSS_E_ENC_INVALID_TYPE:		return "TSS_E_ENC_INVALID_TYPE";
			case TSS_E_INVALID_KEYUSAGE:		return "TSS_E_INVALID_KEYUSAGE";
			case TSS_E_VERIFICATION_FAILED:		return "TSS_E_VERIFICATION_FAILED";
			case TSS_E_HASH_NO_IDENTIFIER:		return "TSS_E_HASH_NO_IDENTIFIER";
			default:	return "UNKNOWN TSS ERROR";
		}
	}
}
