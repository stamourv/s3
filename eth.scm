;;;; Lysiane Bouchard - Vincent St-Amour
;;;; eth.scm

;; Ethernet constants
(define broadcast-mac '#u8(#xff #xff #xff #xff #xff #xff))
(define ethernet-frame-type-ipv4 '#u8(#x08 #x00))
(define ethernet-frame-type-arp  '#u8(#x08 #x06))
(define ethernet-frame-type-rarp '#u8(#x80 #x35))


;; called when a new ethernet frame is received.
(define (eth-pkt-in)
  ;; is it for us ?
  (if (or (u8vector-equal-field? pkt ethernet-destination-mac broadcast-mac 0 6)
	  (u8vector-equal-field? pkt ethernet-destination-mac my-mac 0 6))
      (let ((higher-protocol (u8vector-ref-field pkt ethernet-frame-type 2)))
	(cond ((equal? higher-protocol ethernet-frame-type-ipv4) (ip-pkt-in))
	      ((equal? higher-protocol ethernet-frame-type-arp)  (arp-pkt-in))
	      ((equal? higher-protocol ethernet-frame-type-rarp) (rarp-pkt-in))
	      (else #f)))
      #f))

;; TODO maybe have a more general version that takes the destination as parameter ? would be good for UDP
(define (ethernet-encapsulation len)
  (u8vector-copy! pkt ethernet-source-mac pkt ethernet-destination-mac 6)
  (u8vector-copy! my-mac 0 pkt ethernet-source-mac 6)
  ;; we don't need to set the ethernet frame type, since it's the same as on
  ;; the original packet
  (send-frame (+ 14 len)))
;; TODO pad if necessary up to 46 bytes (does this include the header ?) ? maybe hardware does it
