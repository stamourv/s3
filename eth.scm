;;;; Lysiane Bouchard - Vincent St-Amour
;;;; eth.scm

;; Ethernet constants
(define broadcast-MAC '#u8(#xff #xff #xff #xff #xff #xff))
(define eth-type-IPv4 '#u8(#x08 #x00))
(define eth-type-ARP  '#u8(#x08 #x06))
(define eth-type-RARP '#u8(#x80 #x35))


;; called when a new ethernet frame is received.
(define (eth-pkt-in)
  ;; is it for us ?
  (if (or (u8vector-equal-field? pkt eth-dst-MAC broadcast-MAC 0 6)
	  (u8vector-equal-field? pkt eth-dst-MAC my-MAC 0 6))
      (let ((higher-protocol (u8vector-ref-field pkt eth-type 2)))
	(cond ((equal? higher-protocol eth-type-IPv4) (ip-pkt-in))
	      ((equal? higher-protocol eth-type-ARP)  (arp-pkt-in))
	      ((equal? higher-protocol eth-type-RARP) (rarp-pkt-in))
	      (else #f)))
      #f))

;; TODO maybe have a more general version that takes the destination as parameter ? would be good for UDP
(define (ethernet-encapsulation len)
  (u8vector-copy! pkt eth-src-MAC pkt eth-dst-MAC 6)
  (u8vector-copy! my-MAC 0 pkt eth-src-MAC 6)
  ;; we don't need to set the ethernet frame type, since it's the same as on
  ;; the original packet
  (send-frame (+ 14 len)))
;; TODO pad if necessary up to 46 bytes (does this include the header ?) ? maybe hardware does it
