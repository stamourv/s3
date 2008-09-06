;;;; Lysiane Bouchard - Vincent St-Amour
;;;; ip.scm

;; IP constants
(define ip-protocol-ICMP 1)
(define ip-protocol-TCP  6)
(define ip-protocol-UDP  17)
(define ip-dont-fragment 2)
 ;; TODO enable more addresses ?

;; called when an IP datagram is received
(define (ip-pkt-in)
  ;; TODO do a macro to abstract reception ?
  ;; TODO all these nots are quite ugly, also, do we inline the body of these checks ?
  (cond
   ((not (or (u8vector-equal-field? pkt ip-dst-IP my-IP 0 4) ; is it for us ?
	     (u8vector-equal-field? pkt ip-dst-IP broadcast-IP 0 4)))
    #f)
   ((not (valid-checksum? (compute-ip-checksum)))
    #f)
   ((not (> (u8vector-ref pkt ip-ttl) 0))
    (icmp-send-time-exceed-error))
   ((not (let ((ip-frag-flags (quotient (u8vector-ref pkt ip-frag) 32)))
	   (or (= ip-frag-flags 0)
	       (= ip-frag-flags ip-dont-fragment))))
    (icmp-send-ip-header-bad-error)) ; error, the packet is fragmented TODO we don't handle ? that's the error ?
    (else (let ((higher-protocol (u8vector-ref pkt ip-protocol)))
	   (cond ((= higher-protocol ip-protocol-ICMP) (icmp-pkt-in))
		 ((= higher-protocol ip-protocol-TCP) (tcp-pkt-in))
		 ((= higher-protocol ip-protocol-UDP) (udp-pkt-in))
		 (else (icmp-send-protocol-unreachable-error)))))))

(define (get-ip-hdr-len) (* 4 (modulo (u8vector-ref pkt ip-hdr-len) 16))) ;; TODO no options, so always 20 ?
(define (set-ip-frag)
  (u8vector-set! pkt ip-frag (* ip-dont-fragment 32))
  (u8vector-set! pkt (+ ip-frag 1) 0))
;; TODO where to put these ?

(define (compute-ip-checksum) (pkt-checksum ip-header ip-options 0)) ;; TODO used 3 times, inline ?


;; TODO shouldn't we get the data then return here to encapsulate ? might get rid of some code duplication, and be easier to understand, but we wouldn't have tail calls

(define (ip-encapsulation dst-IP chk-idx compute-checksum len)
  (let ((ip-len (+ 20 len)))
    (u8vector-set! pkt ip-ttl ip-original-ttl)
    (set-ip-frag)
    (integer->pkt 0 ip-checksum 2)
    (u8vector-copy! dst-IP 0 pkt ip-dst-IP 4)
    (u8vector-copy! my-IP 0 pkt ip-src-IP 4)
    (integer->pkt (ip-identification) ip-ident 2)
    (integer->pkt ip-len ip-length 2)
    (u8vector-set! pkt ip-service 0)
    ;; set the version to IPv4 and the header size to 20 bytes (no options)
    ;; which gives : (+ (* 4 16) 5) -> 69
    (u8vector-set! pkt ip-version 69)
    (integer->pkt (reverse-checksum (compute-checksum)) chk-idx 2)
    ;; TODO good order for checksums ?
    (integer->pkt (reverse-checksum (compute-ip-checksum)) ip-checksum 2)
    (ethernet-encapsulation ip-len)))
