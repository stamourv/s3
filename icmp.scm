;;;; Lysiane Bouchard - Vincent St-Amour
;;;; icmp.scm

;; ICMP constants
(define icmp-ip-header-bad '#u8(12 0))
(define icmp-port-unreachable '#u8(3 3))
(define icmp-protocol-unreachable '#u8(3 2))
(define icmp-time-exceeded '#u8(11 0))
(define icmp-parameter-problem  '#u8(12 0))
(define icmp-echo-request '#u8(8 0))
(define icmp-echo-reply '#u8(0 0))
(define icmp-address-mask-request '#u8(17 0))
(define icmp-address-mask-reply '#u8(18 0))
(define icmp-host-precedence-violation '#u8(3 14))


;; called when an icmp datagram is received
(define (icmp-pkt-in) ;; TODO we do have a pattern for protocols, do some checks, then dispatch to an upper level function. the generic reception functions were a pita, maybe try a macro ?
  ;; TODO maybe make sure it's for one of our addresses ?
  (if (= 65535 (compute-icmp-checksum)) ; checksum ok
      ;; dispatch. see eth.scm for justification of the repetition
      (cond ((u8vector-equal-field? pkt icmp-type
				    icmp-echo-request 0 2)
	     (icmp-encapsulation icmp-echo-reply (- (pkt-ref-2 ip-length)
						    ip-header-length
						    icmp-header-length)))
	    ;; TODO if we have a pkt-len var, we wouldn't have to calculate the length like this, it would simply remain unchanged
	    ((u8vector-equal-field? pkt icmp-type
				    icmp-address-mask-request 0 2)
	     (u8vector-copy! my-address-mask 0 pkt icmp-data 4)
	     (icmp-encapsulation icmp-address-mask-reply 4))
	    (else #f)))) ;; TODO remove ?
;; TODO maybe have some better error handling
;; TODO do we accept any other requests ?
;; TODO send error cases to applications, as special tokens when they do the next operation

;; this checksum covers the whole icmp datagram (which ends at the end of the
;; IP datagram)
(define (compute-icmp-checksum)
  (pkt-checksum icmp-header
                (+ ip-header (pkt-ref-2 ip-length))
                0))


(define (icmp-send-ip-header-bad-error) ; TODO wasn't checked, and I can't see it in the rfc
  (u8vector-copy! pkt ip-header pkt icmp-data 20) ; copy IP header
  (icmp-encapsulation icmp-ip-header-bad 20)) ;; TODO used only once, inline ?

;; sets up the packet in case of "unreachable" error, or for a time-exceeded,
;; since it has the same structure
(define (icmp-unreachable type)
  ;; copy IP headers first 20 bytes, and first 8 bytes of data
  (u8vector-copy! pkt udp-header pkt (+ icmp-data 20) 8)
  (u8vector-copy! pkt ip-header pkt icmp-data 20) ; copy IP header
  (integer->pkt 0 icmp-options 4) ; set the 4 optional bytes to 0
  (icmp-encapsulation type (+ 20 8)))


;; data-amount is excluding icmp header
(define (icmp-encapsulation key data-amount)
  (u8vector-copy! key 0 pkt icmp-type 2)
  (integer->pkt 0 icmp-checksum 2)
  ;; unlike other protocols, this change is necessary, since ICMP packets can
  ;; be sent in response to other protocols
  (u8vector-set! pkt ip-protocol ip-protocol-icmp)
  (ip-encapsulation (u8vector-ref-field pkt ip-source-ip 4)
		    icmp-checksum
		    compute-icmp-checksum
		    (+ ip-header-length data-amount icmp-header-length)))
