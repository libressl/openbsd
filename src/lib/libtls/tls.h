/* $OpenBSD: tls.h,v 1.12 2015/03/31 14:03:38 jsing Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HEADER_TLS_H
#define HEADER_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define TLS_API	20141031

#define TLS_PROTOCOL_TLSv1_0	(1 << 1)
#define TLS_PROTOCOL_TLSv1_1	(1 << 2)
#define TLS_PROTOCOL_TLSv1_2	(1 << 3)
#define TLS_PROTOCOL_TLSv1 \
	(TLS_PROTOCOL_TLSv1_0|TLS_PROTOCOL_TLSv1_1|TLS_PROTOCOL_TLSv1_2)

#define TLS_PROTOCOLS_ALL TLS_PROTOCOL_TLSv1
#define TLS_PROTOCOLS_DEFAULT TLS_PROTOCOL_TLSv1_2

#define TLS_READ_AGAIN	-2
#define TLS_WRITE_AGAIN	-3
#define TLS_NO_CERT	-4

struct tls;
struct tls_config;

#define TLS_CERT_GNAME_DNS	1
#define TLS_CERT_GNAME_IPv4	2
#define TLS_CERT_GNAME_IPv6	3
#define TLS_CERT_GNAME_EMAIL	4
#define TLS_CERT_GNAME_URI	5

/*
 * GeneralName
 */
struct tls_cert_general_name {
	const void *name_value;
	int name_type;
};

/*
 * DistinguishedName
 */
struct tls_cert_dname {
	const char *common_name;
	const char *country_name;
	const char *state_or_province_name;
	const char *locality_name;
	const char *street_address;
	const char *organization_name;
	const char *organizational_unit_name;
};

struct tls_cert {
	/* Version number from cert: 0:v1, 1:v2, 2:v3 */
	int version;

	/* did it pass verify?  useful when noverifycert is on. */
	int successful_verify;

	/* DistringuishedName for subject */
	struct tls_cert_dname subject;

	/* DistringuishedName for issuer */
	struct tls_cert_dname issuer;

	/* SubjectAltName extension */
	struct tls_cert_general_name *subject_alt_names;
	int subject_alt_name_count;

	/* decimal number */
	const char *serial;

	/* Validity times in ISO 8601 format: 2015-08-18T06:36:40Z */
	const char *not_before;
	const char *not_after;

	/* Fingerprint as raw hash */
	const unsigned char *fingerprint;
	size_t fingerprint_size;
};

int tls_init(void);

const char *tls_error(struct tls *_ctx);

struct tls_config *tls_config_new(void);
void tls_config_free(struct tls_config *_config);

int tls_config_set_ca_file(struct tls_config *_config, const char *_ca_file);
int tls_config_set_ca_path(struct tls_config *_config, const char *_ca_path);
int tls_config_set_ca_mem(struct tls_config *_config, const uint8_t *_ca,
    size_t _len);
int tls_config_set_cert_file(struct tls_config *_config,
    const char *_cert_file);
int tls_config_set_cert_mem(struct tls_config *_config, const uint8_t *_cert,
    size_t _len);
int tls_config_set_ciphers(struct tls_config *_config, const char *_ciphers);
int tls_config_set_dheparams(struct tls_config *_config, const char *_params);
int tls_config_set_ecdhecurve(struct tls_config *_config, const char *_name);
int tls_config_set_key_file(struct tls_config *_config, const char *_key_file);
int tls_config_set_key_mem(struct tls_config *_config, const uint8_t *_key,
    size_t _len);
void tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols);
void tls_config_set_verify_depth(struct tls_config *_config, int _verify_depth);

void tls_config_clear_keys(struct tls_config *_config);
int tls_config_parse_protocols(uint32_t *_protocols, const char *_protostr);

void tls_config_insecure_noverifycert(struct tls_config *_config);
void tls_config_insecure_noverifyname(struct tls_config *_config);
void tls_config_verify(struct tls_config *_config);

struct tls *tls_client(void);
struct tls *tls_server(void);
int tls_configure(struct tls *_ctx, struct tls_config *_config);
void tls_reset(struct tls *_ctx);
void tls_free(struct tls *_ctx);

int tls_accept_fds(struct tls *_ctx, struct tls **_cctx, int _fd_read,
    int _fd_write);
int tls_accept_socket(struct tls *_ctx, struct tls **_cctx, int _socket);
int tls_connect(struct tls *_ctx, const char *_host, const char *_port);
int tls_connect_fds(struct tls *_ctx, int _fd_read, int _fd_write,
    const char *_servername);
int tls_connect_servername(struct tls *_ctx, const char *_host,
    const char *_port, const char *_servername);
int tls_connect_socket(struct tls *_ctx, int _s, const char *_servername);
int tls_read(struct tls *_ctx, void *_buf, size_t _buflen, size_t *_outlen);
int tls_write(struct tls *_ctx, const void *_buf, size_t _buflen,
    size_t *_outlen);
int tls_close(struct tls *_ctx);

uint8_t *tls_load_file(const char *_file, size_t *_len, char *_password);

int tls_get_peer_cert(struct tls *ctx, struct tls_cert **cert_p, const char *fingerprint_algo);
void tls_cert_free(struct tls_cert *cert);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_TLS_H */
