#	$OpenBSD: Makefile,v 1.56 2024/03/26 01:18:16 beck Exp $

SUBDIR += api
SUBDIR += asn1
SUBDIR += buffer
SUBDIR += bytestring
SUBDIR += ciphers
#Disable for now for upcoming changes. This needs to be easier to deal with.
#SUBDIR += client
SUBDIR += dtls
SUBDIR += exporter
SUBDIR += handshake
SUBDIR += pqueue
SUBDIR += quic
SUBDIR += record
SUBDIR += record_layer
SUBDIR += server
SUBDIR += shutdown
SUBDIR += ssl
SUBDIR += symbols
SUBDIR += tls
SUBDIR += tlsext
SUBDIR += tlslegacy
SUBDIR += key_schedule
SUBDIR += unit
SUBDIR += verify

# Things that take a long time should go below here. 
SUBDIR += openssl-ruby
SUBDIR += rust-openssl
SUBDIR += tlsfuzzer
SUBDIR += interop

install:

.include <bsd.subdir.mk>
