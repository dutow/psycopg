"""
psycopg_c.pq OAuth / OAUTHBEARER authentication support.
"""

# Copyright (C) 2020 The Psycopg Team

from libc.stdlib cimport free
from libc.string cimport strdup

import threading

from psycopg import errors as e


cdef object _auth_data_hook_lock = threading.Lock()
cdef object _auth_data_hook_callback = None


cdef class PromptOAuthDevice:
    """Read-only wrapper around a PGpromptOAuthDevice struct."""

    cdef libpq.PGpromptOAuthDevice *_ptr

    @staticmethod
    cdef PromptOAuthDevice _from_ptr(libpq.PGpromptOAuthDevice *ptr):
        cdef PromptOAuthDevice self = PromptOAuthDevice.__new__(PromptOAuthDevice)
        self._ptr = ptr
        return self

    cdef _invalidate(self):
        self._ptr = NULL

    cdef _ensure_valid(self):
        if self._ptr is NULL:
            raise e.OperationalError(
                "PromptOAuthDevice is no longer valid outside the callback"
            )

    @property
    def verification_uri(self) -> str:
        self._ensure_valid()
        if self._ptr.verification_uri is not NULL:
            return self._ptr.verification_uri.decode()
        return ""

    @property
    def user_code(self) -> str:
        self._ensure_valid()
        if self._ptr.user_code is not NULL:
            return self._ptr.user_code.decode()
        return ""

    @property
    def verification_uri_complete(self):
        self._ensure_valid()
        if self._ptr.verification_uri_complete is not NULL:
            return self._ptr.verification_uri_complete.decode()
        return None

    @property
    def expires_in(self) -> int:
        self._ensure_valid()
        return self._ptr.expires_in


cdef class OAuthBearerRequest:
    """Wrapper around a PGoauthBearerRequest struct."""

    cdef libpq.PGoauthBearerRequest *_ptr
    cdef char *_token_copy

    @staticmethod
    cdef OAuthBearerRequest _from_ptr(libpq.PGoauthBearerRequest *ptr):
        cdef OAuthBearerRequest self = OAuthBearerRequest.__new__(OAuthBearerRequest)
        self._ptr = ptr
        self._token_copy = NULL
        return self

    cdef _invalidate(self):
        self._ptr = NULL

    cdef _ensure_valid(self):
        if self._ptr is NULL:
            raise e.OperationalError(
                "OAuthBearerRequest is no longer valid outside the callback"
            )

    @property
    def openid_configuration(self) -> str:
        self._ensure_valid()
        cdef const char *v = libpq.pq_oauth_get_openid_configuration(self._ptr)
        if v is not NULL:
            return v.decode()
        return ""

    @property
    def scope(self):
        self._ensure_valid()
        cdef const char *v = libpq.pq_oauth_get_scope(self._ptr)
        if v is not NULL:
            return v.decode()
        return None

    @property
    def token(self):
        self._ensure_valid()
        cdef char *v = libpq.pq_oauth_get_token(self._ptr)
        if v is not NULL:
            return v.decode()
        return None

    @token.setter
    def token(self, value):
        self._ensure_valid()
        # Free any previous copy
        if self._token_copy is not NULL:
            free(self._token_copy)
            self._token_copy = NULL

        if value is not None:
            bval = value.encode()
            self._token_copy = strdup(<const char *>bval)
            if self._token_copy is NULL:
                raise MemoryError("couldn't allocate token copy")
            libpq.pq_oauth_set_token(self._ptr, self._token_copy)
        else:
            libpq.pq_oauth_set_token(self._ptr, NULL)


cdef void _oauth_bearer_cleanup(
    libpq.PGconn *conn,
    libpq.PGoauthBearerRequest *req,
) noexcept nogil:
    """Cleanup callback that frees the strdup'd token."""
    cdef char *tok = libpq.pq_oauth_get_token(req)
    if tok is not NULL:
        free(tok)
        libpq.pq_oauth_set_token(req, NULL)


cdef int _auth_data_hook_proxy(
    libpq.PGauthData type_,
    libpq.PGconn *conn,
    void *data,
) noexcept with gil:
    """C callback proxy that acquires GIL and delegates to Python hook."""
    global _auth_data_hook_callback

    cdef object hook
    with _auth_data_hook_lock:
        hook = _auth_data_hook_callback

    if hook is None:
        with nogil:
            return libpq.PQdefaultAuthDataHook(type_, conn, data)

    try:
        if type_ == libpq.PQAUTHDATA_PROMPT_OAUTH_DEVICE:
            wrapper = PromptOAuthDevice._from_ptr(
                <libpq.PGpromptOAuthDevice *>data
            )
            try:
                return 1 if hook(wrapper) else 0
            finally:
                wrapper._invalidate()

        elif type_ == libpq.PQAUTHDATA_OAUTH_BEARER_TOKEN:
            req_wrapper = OAuthBearerRequest._from_ptr(
                <libpq.PGoauthBearerRequest *>data
            )
            # Set cleanup callback to free the token
            libpq.pq_oauth_set_cleanup(
                <libpq.PGoauthBearerRequest *>data,
                _oauth_bearer_cleanup
            )
            try:
                return 1 if hook(req_wrapper) else 0
            finally:
                req_wrapper._invalidate()

        else:
            with nogil:
                return libpq.PQdefaultAuthDataHook(type_, conn, data)

    except Exception:
        logger.exception("error in auth data hook")
        return -1


def set_auth_data_hook(callback=None):
    """Set a global hook for OAuth authentication data.

    The callback receives either a PromptOAuthDevice or OAuthBearerRequest
    object and should return True to indicate it handled the request.

    Pass None (or no argument) to reset to the default libpq hook.
    """
    global _auth_data_hook_callback

    if libpq.PG_VERSION_NUM < 180000:
        raise e.NotSupportedError(
            "set_auth_data_hook requires libpq from PostgreSQL 18 or later"
        )

    with _auth_data_hook_lock:
        _auth_data_hook_callback = callback
        if callback is not None:
            libpq.PQsetAuthDataHook(_auth_data_hook_proxy)
        else:
            libpq.PQsetAuthDataHook(libpq.PQdefaultAuthDataHook)


def get_auth_data_hook():
    """Return the current auth data hook callback, or None if not set."""
    if libpq.PG_VERSION_NUM < 180000:
        raise e.NotSupportedError(
            "get_auth_data_hook requires libpq from PostgreSQL 18 or later"
        )

    with _auth_data_hook_lock:
        return _auth_data_hook_callback
