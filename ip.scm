;;;; Lysiane Bouchard - Vincent St-Amour
;;;; ip.scm

;; IP constants
(define ip-protocol-icmp 1)
(define ip-protocol-tcp  6)
(define ip-protocol-udp  17)
(define ip-dont-fragment 2)
 ;; TODO enable more addresses ?

;; called when an IP datagram is received
;; it should be noted that any datagram containing options will be rejected
;; since we do not support options
(define (ip-pkt-in)
  ;; TODO do a macro to abstract reception ?
  ;; TODO all these nots are quite ugly, also, do we inline the body of these checks ?
  (cond
   ((not (or (u8vector-equal-field? pkt ip-destination-ip my-ip 0 4) ; is it for us ?
	     (u8vector-equal-field? pkt ip-destination-ip broadcast-ip 0 4)))
    #f)
   ;; if the packet has IP options (header longer than 20 bytes), we reject it
   ;; since the header length we accept is only 20, and the version is always
   ;; 4, we only have to see if the byte is equal to (4 << 4) + (20 / 4) = 69
   ((not (= (u8vector-ref pkt ip-version-and-header-length) 69))
    #f)
   ((not (= 65535 (pkt-checksum ip-header ip-options 0)))
    #f)
   ((not (> (u8vector-ref pkt ip-time-to-live) 0))
    (icmp-unreachable icmp-time-exceeded))
   ((not (let ((ip-frag-flags (quotient (u8vector-ref pkt ip-fragment-offset)
					32)))
	   (or (= ip-frag-flags 0)
	       (= ip-frag-flags ip-dont-fragment))))
    (icmp-send-ip-header-bad-error)) ; error, the packet is fragmented TODO we don't handle ? that's the error ?
    (else (let ((higher-protocol (u8vector-ref pkt ip-protocol)))
	   (cond ((= higher-protocol ip-protocol-icmp) (icmp-pkt-in))
		 ((= higher-protocol ip-protocol-tcp)  (tcp-pkt-in))
		 ((= higher-protocol ip-protocol-udp)  (udp-pkt-in))
		 (else (icmp-unreachable icmp-protocol-unreachable)))))))


(define (ip-encapsulation destination-ip chk-idx compute-checksum len)
  (let ((ip-len (+ 20 len)))
    (u8vector-set! pkt ip-time-to-live ip-original-time-to-live)
    (u8vector-set! pkt ip-fragment-offset (* ip-dont-fragment 32))
    (u8vector-set! pkt (+ ip-fragment-offset 1) 0) ;; TODO should we support fragementation ?
    (integer->pkt 0 ip-checksum 2)
    (u8vector-copy! destination-ip 0 pkt ip-destination-ip 4)
    (u8vector-copy! my-ip 0 pkt ip-source-ip 4)
    (integer->pkt (get-ip-identification) ip-identification 2)
    (integer->pkt ip-len ip-length 2)
    ;; we don't need to set the header length and version, since it does not
    ;; change, and we always send an IP datagram in response to another
    (u8vector-set! pkt ip-service 0)
    ;; higher-protocol chacksums must be calculated when the IP header is set
    ;; we therefore cannot calculate it during the higher-protocol encapsulation
    (integer->pkt (bitwise-xor 65535 (compute-checksum)) chk-idx 2)
    (integer->pkt (bitwise-xor 65535 (pkt-checksum ip-header ip-options 0))
		  ip-checksum 2)
    (ethernet-encapsulation ip-len)))
